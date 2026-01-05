import argparse
import csv
import logging
import os
import select
import socket
import time
import uuid
import sys
import errno
import queue
import threading
import secrets
from datetime import datetime, UTC

# logging básico por si no existe logging_conf en tu repo
try:
    from logging_conf import setup_logging
    logger = setup_logging()
except Exception:
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    logger = logging.getLogger("app")

from sip_manager import (
    SIPManager,
    build_options,
    build_response,
    build_invite,
    build_ack,
    build_bye,
    parse_headers,
    status_from_response,
    build_cancel,
    build_trying,
    build_ringing,
    build_200,
    build_487,
)
from sdp import (
    build_sdp,
    parse_sdp,
    PT_FROM_CODEC_NAME,
    CODEC_NAME_FROM_PT,
    DIRECTION_SET,
    parse_direction_from_sdp,
    direction_to_flags,
    flags_to_direction,
    intersect_answer,
)
from rtp import RtpSession
from core.reactor import Reactor
from core.options_monitor import OptionsMonitor, register_options_responder
from socket_handler import SipTransport, get_sip_transport

PROHIBITED = {"via", "from", "to", "call-id", "cseq", "contact", "content-length"}


class SIPDialog:
    def __init__(self, call_id, local_tag):
        self.call_id = call_id
        self.local_tag = local_tag
        self.remote_tag = None
        self.cseq = 1
        self.established = False
        self.ack_sent = False
        self.rtp = None
        self.remote_rtp = None  # (ip, port)
        self.mode = "sendrecv"  # a=sendrecv|sendonly|recvonly|inactive
        self.timer_cancel = None
        self.extra_headers = []
        self.branch = None


def parse_sdp_for_audio(sdp_text):
    # devuelve (ip, port, payloads[], mode)
    ip = None
    port = None
    pts = []
    mode = "sendrecv"
    for line in sdp_text.splitlines():
        line = line.strip()
        if line.startswith("c="):
            parts = line.split()
            if len(parts) >= 3:
                ip = parts[-1]
        elif line.startswith("m=audio"):
            parts = line.split()
            if len(parts) >= 4:
                try:
                    port = int(parts[1])
                except ValueError:
                    port = None
                pts = [int(p) for p in parts[3:] if p.isdigit()]
        elif line == "a=sendonly":
            mode = "sendonly"
        elif line == "a=recvonly":
            mode = "recvonly"
        elif line == "a=inactive":
            mode = "inactive"
    return ip, port, pts, mode


def build_identities(args):
    # Normaliza variables para construir URIs y cabeceras
    from_user = getattr(args, "from_user", None)
    to_user = getattr(args, "to_user", None)
    from_domain = getattr(args, "from_domain", None)
    to_domain = getattr(args, "to_domain", None)

    from_uri = getattr(args, "from_uri", None) or (
        f"sip:{from_user}@{from_domain}" if from_user and from_domain else None
    )
    to_uri = getattr(args, "to_uri", None) or (
        f"sip:{to_user}@{to_domain}" if to_user and to_domain else None
    )

    extra_headers = []
    raw = getattr(args, "extra_headers", "") or ""
    for line in str(raw).splitlines():
        h = line.strip()
        if h:
            extra_headers.append(h)

    return from_uri, to_uri, extra_headers


def start_rtp_for_dialog(
    dialog: SIPDialog,
    local_ip,
    rtp_port,
    payload_pt,
    tone_hz,
    send_silence,
    remote_ip,
    remote_port,
):
    dialog.remote_rtp = (remote_ip, remote_port)
    if dialog.mode == "inactive":
        return
    send_enabled = dialog.mode in ("sendrecv", "sendonly")
    recv_enabled = dialog.mode in ("sendrecv", "recvonly")
    force_silence = send_silence or dialog.mode == "sendonly"
    dialog.rtp = RtpSession(local_ip, rtp_port, payload_pt, forced=True)
    dialog.rtp.tone_hz = tone_hz
    dialog.rtp.send_silence = force_silence and not tone_hz
    dialog.rtp.set_sending(send_enabled)
    dialog.rtp.set_receiving(recv_enabled)
    dialog.rtp.start(remote_ip, remote_port)


def stop_rtp_for_dialog(dialog: SIPDialog):
    if dialog and dialog.rtp:
        try:
            dialog.rtp.stop()
        except Exception:
            pass
        dialog.rtp = None


def schedule_cancel_if_ringing(sock, dst, dialog: SIPDialog, timeout_s, send_cancel_fn):
    def _t():
        if not dialog.established:
            send_cancel_fn(sock, dst, dialog)

    dialog.timer_cancel = threading.Timer(timeout_s, _t)
    dialog.timer_cancel.start()


def clear_cancel_timer(dialog: SIPDialog):
    if dialog and dialog.timer_cancel:
        try:
            dialog.timer_cancel.cancel()
        except Exception:
            pass
        dialog.timer_cancel = None


def _extract_tag(header_value: str | None) -> str | None:
    if not header_value:
        return None
    lower = header_value.lower()
    if "tag=" not in lower:
        return None
    idx = lower.find("tag=")
    tag = header_value[idx + 4 :]
    for sep in (";", ">", " "):
        if sep in tag:
            tag = tag.split(sep, 1)[0]
    return tag.strip() or None


def _coerce_payloads(codecs):
    if not codecs:
        return [(0, "PCMU"), (8, "PCMA")]
    if isinstance(codecs, str):
        items = [c.strip().lower() for c in codecs.split(",") if c.strip()]
    else:
        items = list(codecs)
    payloads = []
    for item in items:
        if isinstance(item, tuple) and len(item) >= 2:
            payloads.append((int(item[0]), str(item[1]).upper()))
            continue
        if isinstance(item, str):
            pt = PT_FROM_CODEC_NAME.get(item.lower())
            if pt is not None:
                payloads.append((pt, item.upper()))
    return payloads or [(0, "PCMU"), (8, "PCMA")]


def build_response_ok_from_request(request_data: bytes) -> bytes:
    start, headers = parse_headers(request_data)
    if not start:
        return b""
    resp_headers = {
        "Via": headers.get("via", ""),
        "From": headers.get("from", ""),
        "To": headers.get("to", ""),
        "Call-ID": headers.get("call-id", ""),
        "CSeq": headers.get("cseq", ""),
        "User-Agent": "Dimitri-4000/0.1",
    }
    return build_response(200, "OK", resp_headers)


def build_bye_simple(
    request_uri: str,
    from_uri: str,
    to_uri: str,
    local_ip: str,
    local_port: int,
    call_id: str,
    cseq: int,
    from_tag: str,
    to_tag: str | None,
    contact_user: str,
) -> bytes:
    branch = "z9hG4bK" + uuid.uuid4().hex
    from_hdr = f"<{from_uri}>;tag={from_tag}"
    to_hdr = f"<{to_uri}>"
    if to_tag:
        to_hdr = f"{to_hdr};tag={to_tag}"
    msg = (
        f"BYE {request_uri} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {local_ip}:{local_port};branch={branch};rport\r\n"
        "Max-Forwards: 70\r\n"
        f"From: {from_hdr}\r\n"
        f"To: {to_hdr}\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: {cseq} BYE\r\n"
        f"Contact: <sip:{contact_user}@{local_ip}:{local_port}>\r\n"
        "User-Agent: Dimitri-4000/0.1\r\n"
        "Content-Length: 0\r\n\r\n"
    )
    return msg.encode()


def generator_call_worker(
    transport: SipTransport,
    sip_ip: str,
    sip_port: int,
    sdp_ip: str,
    dst_addr,
    base_args,
    per_call_args,
    call_id: str,
    rx_queue,
    stats_cb=None,
):
    """
    sock: UDP ya bindeado (puerto src)
    dst_addr: (ip, port) destino
    base_args: namespace global del generador
    per_call_args: namespace con from_uri/to_uri, rtp_port, codecs, etc. de esta llamada
    """
    log = logging.getLogger("load-call")
    start_ts = time.time()
    local_tag = secrets.token_hex(4)
    dialog = SIPDialog(call_id, local_tag)

    codecs = _coerce_payloads(
        getattr(per_call_args, "codecs", None) or getattr(base_args, "codecs", None)
    )
    pt_prefer = codecs[0][0]
    sdp_mode = getattr(per_call_args, "sdp_mode", None) or getattr(
        base_args, "sdp_mode", None
    )
    if not sdp_mode:
        sdp_mode = getattr(base_args, "sdp_direction", "sendrecv")
    dialog.mode = sdp_mode
    offer_sdp = build_sdp(
        sdp_ip,
        per_call_args.rtp_port,
        codecs,
        session_extras=getattr(base_args, "sdp_session_extras", []),
        media_extras=getattr(base_args, "sdp_extras", []),
        direction=sdp_mode,
    )

    cseq = dialog.cseq
    branch = "z9hG4bK" + uuid.uuid4().hex
    dialog.branch = branch
    contact_user = getattr(per_call_args, "from_user", None) or "u"
    local_port = sip_port
    invite = build_invite(
        request_uri=per_call_args.to_uri,
        from_uri=per_call_args.from_uri,
        to_uri=per_call_args.to_uri,
        local_ip=sip_ip,
        local_port=local_port,
        call_id=call_id,
        cseq=cseq,
        tag=local_tag,
        branch=branch,
        sdp=offer_sdp,
        contact_user=contact_user,
        extra_headers=getattr(per_call_args, "extra_headers_list", []),
    )
    transport.sendto(invite, dst_addr)

    ring_timeout = float(getattr(base_args, "ring_timeout", 10.0))
    ring_deadline = time.time() + ring_timeout

    established = False
    bye_sent = False
    setup_ms = 0
    result = "aborted"
    talk_time = float(getattr(base_args, "talk_time", 0) or 0)
    max_call_time = float(getattr(base_args, "max_call_time", 0) or 0)
    t_end = time.time() + talk_time if talk_time > 0 else None
    max_end = time.time() + max_call_time if max_call_time > 0 else None

    while True:
        now = time.time()
        if not established and now > ring_deadline:
            cancel = build_cancel(
                request_uri=per_call_args.to_uri,
                to_uri=per_call_args.to_uri,
                local_ip=sip_ip,
                local_port=local_port,
                from_uri=per_call_args.from_uri,
                from_display=None,
                call_id=call_id,
                cseq=cseq,
                tag=local_tag,
                branch=branch,
                contact_user=contact_user,
            )
            transport.sendto(cancel, dst_addr)
            log.info("CANCEL enviado call-id=%s", call_id)
            result = "canceled"
            break

        if established and talk_time > 0 and t_end and now >= t_end and not bye_sent:
            bye = build_bye_simple(
                request_uri=per_call_args.to_uri,
                from_uri=per_call_args.from_uri,
                to_uri=per_call_args.to_uri,
                local_ip=local_ip,
                local_port=local_port,
                call_id=call_id,
                cseq=dialog.cseq + 1,
                from_tag=local_tag,
                to_tag=dialog.remote_tag,
                contact_user=contact_user,
            )
            transport.sendto(bye, dst_addr)
            bye_sent = True
            result = "max-time-bye"

        if established and max_end and now >= max_end and not bye_sent:
            bye = build_bye_simple(
                request_uri=per_call_args.to_uri,
                from_uri=per_call_args.from_uri,
                to_uri=per_call_args.to_uri,
                local_ip=local_ip,
                local_port=local_port,
                call_id=call_id,
                cseq=dialog.cseq + 1,
                from_tag=local_tag,
                to_tag=dialog.remote_tag,
                contact_user=contact_user,
            )
            transport.sendto(bye, dst_addr)
            bye_sent = True
            result = "max-time-bye"

        try:
            data, addr = rx_queue.get(timeout=0.5)
        except queue.Empty:
            continue
        except OSError:
            result = "aborted"
            break

        msg_start, headers = parse_headers(data)
        if headers.get("call-id") != call_id:
            continue

        cseq_hdr = headers.get("cseq", "")
        if msg_start.startswith("SIP/2.0") and "200" in msg_start and "INVITE" in cseq_hdr:
            dialog.remote_tag = _extract_tag(headers.get("to"))
            body = b""
            if b"\r\n\r\n" in data:
                body = data.split(b"\r\n\r\n", 1)[1]
            sdp_text = body.decode("utf-8", "ignore")
            rip, rport, _, mode = parse_sdp_for_audio(sdp_text)
            dialog.mode = mode or dialog.mode
            ack = build_ack(
                request_uri=per_call_args.to_uri,
                to_header=headers.get("to", f"<{per_call_args.to_uri}>"),
                local_ip=sip_ip,
                local_port=local_port,
                from_uri=per_call_args.from_uri,
                from_display=None,
                call_id=call_id,
                cseq=cseq,
                tag=local_tag,
                contact_user=contact_user,
            )
            transport.sendto(ack, dst_addr)
            dialog.ack_sent = True
            established = True
            dialog.established = True
            setup_ms = int((time.time() - start_ts) * 1000)
            if result == "aborted":
                result = "answered"
            if rip and rport:
                try:
                    start_rtp_for_dialog(
                        dialog,
                        sdp_ip,
                        per_call_args.rtp_port,
                        pt_prefer,
                        getattr(base_args, "rtp_tone", 0) or 0,
                        bool(getattr(base_args, "rtp_send_silence", False)),
                        rip,
                        rport,
                    )
                except Exception as exc:
                    log.warning("RTP no pudo iniciar call-id=%s: %s", call_id, exc)
                log.info("ACK enviado y RTP iniciado call-id=%s -> %s:%s", call_id, rip, rport)
            if stats_cb:
                try:
                    stats_cb(
                        {
                            "type": "uac_established",
                            "call_id": call_id,
                            "local_port": local_port,
                            "remote_ip": rip,
                            "remote_port": rport,
                        }
                    )
                except Exception:
                    pass
            continue

        if msg_start.startswith("BYE "):
            resp = build_response_ok_from_request(data)
            if resp:
                transport.sendto(resp, addr)
            stop_rtp_for_dialog(dialog)
            log.info("BYE remoto atendido call-id=%s", call_id)
            result = "remote-bye" if established else "aborted"
            break

        if msg_start.startswith("SIP/2.0") and "200" in msg_start and "BYE" in cseq_hdr:
            stop_rtp_for_dialog(dialog)
            log.info("200 OK a BYE recibido call-id=%s", call_id)
            if result == "aborted":
                result = "max-time-bye" if bye_sent else "answered"
            break

    stop_rtp_for_dialog(dialog)
    if stats_cb and established:
        try:
            stats_cb({"type": "uac_ended", "call_id": call_id})
        except Exception:
            pass
    if not established and result == "aborted":
        result = "aborted"
    return call_id, result, setup_ms, dialog


def sanitize_extra_headers(raw, *, log=None) -> list[str]:
    """Return sanitized SIP headers ignoring protected ones."""

    log = log or logger
    entries: list[str] = []
    if raw is None:
        items: list[str] = []
    elif isinstance(raw, str):
        items = raw.replace("\r", "").split("\n")
    else:
        items = []
        for elem in raw:
            if not isinstance(elem, str):
                continue
            items.extend(elem.replace("\r", "").split("\n"))
    for ln in items:
        line = ln.strip()
        if not line:
            continue
        if ":" not in line:
            if log:
                log.warning("Cabecera extra inválida (sin ':'): %s", line)
            continue
        name, value = line.split(":", 1)
        header = name.strip()
        if header.lower() in PROHIBITED:
            if log:
                log.warning(
                    "Cabecera extra ignorada: no se permite sobreescribir %s", header
                )
            continue
        entries.append(f"{header}: {value.strip()}")
    return entries


def _parse_extra_headers(raw, *, log=None) -> list[str]:
    """Normalize optional extra headers to a sanitized list of strings."""

    if raw is None:
        return []
    log = log or logger
    if isinstance(raw, dict):
        iterable = raw.items()
    elif isinstance(raw, str):
        iterable = [raw]
    else:
        try:
            iterable = list(raw)
        except TypeError:
            iterable = []
    items: list[str] = []
    for entry in iterable:
        if isinstance(entry, str):
            items.append(entry)
        elif isinstance(entry, (tuple, list)) and len(entry) == 2:
            name, value = entry
            name_str = str(name).strip()
            value_str = str(value).strip()
            if not name_str:
                continue
            items.append(f"{name_str}: {value_str}")
    if not items and isinstance(raw, str):
        items = [raw]
    return sanitize_extra_headers(items, log=log)


def write_csv_row(path, row, header=None):
    new_file = not os.path.exists(path)
    with open(path, "a", newline="") as f:
        w = csv.writer(f)
        if new_file and header:
            w.writerow(header)
        w.writerow(row)


def _get_flag(obj, name):
    return bool(getattr(obj, name, False))


def _norm_sip_uri(user: str | None, domain: str | None, uri: str | None) -> str | None:
    """
    Devuelve una URI sip canónica:
      - si viene `uri`, lo normaliza (añade 'sip:' si falta).
      - si no, intenta con user/domain (user puede ser from_user o from_number).
      - si no hay datos suficientes, devuelve None.
    """
    if uri:
        u = uri.strip()
        if not u:
            return None
        return u if u.lower().startswith("sip:") else f"sip:{u}"
    if user and domain:
        return f"sip:{user}@{domain}"
    return None


def _require(value, label, logger=None):
    if value is None or (isinstance(value, str) and not value.strip()):
        if logger:
            logger.error(f"LOAD: falta {label}; abortando esta llamada")
        raise ValueError(f"missing {label}")
    return value


def send_options_periodic(
    bind_ip: str | None,
    src_port: int,
    dst_host: str,
    dst_port: int,
    interval: float,
    timeout: float,
    cseq_start: int = 1,
    stop_event: threading.Event | None = None,
    cb=None,
    extra_headers: list[str] | None = None,
):
    """Send SIP OPTIONS periodically until stop_event is set."""
    sm = SIPManager(protocol="udp")
    cseq = cseq_start
    counters = {"sent": 0, "ok": 0, "other": 0, "timeout": 0, "last": "-"}
    stop_event = stop_event or threading.Event()
    while not stop_event.is_set():
        counters["sent"] += 1
        try:
            code, _, _ = sm.send_request(
                dst_host=dst_host,
                dst_port=dst_port,
                timeout=timeout,
                bind_ip=bind_ip,
                bind_port=src_port,
                cseq=cseq,
                extra_headers=extra_headers,
            )
        except OSError:
            counters["other"] += 1
            counters["last"] = "error"
        else:
            if code is None:
                counters["timeout"] += 1
                counters["last"] = "timeout"
            elif code == 200:
                counters["ok"] += 1
                counters["last"] = "200"
            else:
                counters["other"] += 1
                counters["last"] = str(code)
        if cb:
            cb(counters.copy())
        cseq += 1
        if stop_event.wait(interval):
            break
    return counters


def parse_args():
    p = argparse.ArgumentParser(description="Dimitri 4000 - Monitor SIP OPTIONS")
    # CLI moderna
    p.add_argument("--dst", help="Host/IP destino SIP")
    p.add_argument("--dst-port", type=int, default=5060, help="Puerto SIP destino")
    p.add_argument("--protocol", choices=["udp", "tcp"], default="udp", help="Transporte")
    p.add_argument("--interval", type=float, default=1.0, help="Intervalo entre envíos (s)")
    p.add_argument("--timeout", type=float, default=2.0, help="Timeout de socket (s)")
    p.add_argument("--count", type=int, default=1, help="Número de OPTIONS a enviar")
    p.add_argument("--bind-ip", default=None, help="IP local desde la que salir (opcional)")
    p.add_argument(
        "--src-port",
        type=int,
        default=0,
        help="Puerto UDP de origen (0 = efímero)",
    )
    p.add_argument("--advertised-ip", help="IP anunciada en Contact/SDP", default=None)
    p.add_argument("--cseq-start", type=int, default=1, help="CSeq inicial (por defecto 1)")
    p.add_argument("--service", action="store_true", help="Modo servicio continuo")
    p.add_argument("--gui", action="store_true", help="Inicia interfaz gráfica Tkinter")
    p.add_argument("--tui", action="store_true", help="Inicia interfaz curses retro")
    p.add_argument("--uas", action="store_true", help="Habilita servidor SIP UAS")
    p.add_argument(
        "--single-socket",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Usar un único socket UDP compartido",
    )
    p.add_argument("--options-monitor", action="store_true", help="Monitor OPTIONS en CLI")
    p.add_argument(
        "--uas-ring-delay",
        type=float,
        default=1.0,
        help="Tiempo desde INVITE hasta enviar 180 Ringing",
    )
    p.add_argument(
        "--uas-answer-after",
        type=float,
        default=2.0,
        help="Tiempo desde INVITE hasta responder 200 OK",
    )
    p.add_argument(
        "--uas-talk-time",
        type=float,
        default=0.0,
        help="Si >0, tras ACK enviar BYE a los N segundos",
    )
    p.add_argument(
        "--uas-rtp-port",
        type=int,
        default=40002,
        help="Puerto RTP anunciado por el UAS",
    )
    p.add_argument(
        "--reply-options",
        action="store_true",
        help="Responder 200 OK a OPTIONS entrantes",
    )
    p.add_argument("--invite", action="store_true", help="Realizar una llamada básica")
    p.add_argument("--to", help="URI destino para INVITE (compat)")
    p.add_argument("--from-user", default="dimitri", help="Usuario origen (compat)")
    p.add_argument("--from-number", help="Número origen (From)")
    p.add_argument("--from-domain", help="Dominio From")
    p.add_argument("--from-display", help="Display name From")
    p.add_argument("--to-number", help="Número destino (To)")
    p.add_argument("--to-domain", help="Dominio To")
    p.add_argument("--from-uri", help="URI completa From (sip:...)")
    p.add_argument("--to-uri", help="URI completa To (sip:...)")
    p.add_argument("--pai", help="URI para P-Preferred/Asserted-Identity")
    p.add_argument("--use-pai", action="store_true", help="Añadir P-Preferred-Identity")
    p.add_argument("--use-pai-asserted", action="store_true", help="Añadir P-Asserted-Identity")
    p.add_argument("--ring-timeout", type=float, default=15.0, help="Tiempo de espera antes de cancelar")
    p.add_argument("--talk-time", type=float, default=5.0, help="Tiempo de conversación antes de enviar BYE")
    p.add_argument(
        "--wait-bye",
        action="store_true",
        help="Si está, tras 200/ACK el UAC espera BYE remoto",
    )
    p.add_argument(
        "--max-call-time",
        type=float,
        default=0.0,
        help="Segundos; si se supera sin BYE, enviar BYE y cerrar (0=infinito)",
    )
    p.add_argument(
        "--codecs",
        default="pcmu,pcma",
        help="Lista de códecs permitidos/orden de preferencia",
    )
    p.add_argument(
        "--allow-unsupported-codecs",
        action="store_true",
        help="Permite anunciar PTs no soportados solo en la oferta SDP",
    )
    p.add_argument(
        "--codec",
        choices=["pcmu", "pcma"],
        help="(compat) equivalente a --codecs <valor>",
    )
    p.add_argument(
        "--prefer",
        choices=["pcmu", "pcma"],
        help="Si ambos están disponibles, fuerza preferencia local",
    )
    p.add_argument("--rtp-port", type=int, default=40000, help="Puerto RTP local")
    p.add_argument("--rtcp", action="store_true", help="Abrir puerto RTCP")
    p.add_argument("--rtp-tone", type=int, help="Enviar tono continuo (Hz)")
    p.add_argument("--rtp-send-silence", action="store_true", help="Enviar silencio si no hay tono")
    p.add_argument(
        "--rtp-always-silence",
        action="store_true",
        help="Forzar envío de silencio si no se especifica tono",
    )
    p.add_argument("--symmetric-rtp", action="store_true", help="Aprender IP:puerto remoto de RTP")
    p.add_argument("--rtp-save-wav", help="Guardar audio recibido a WAV")
    p.add_argument(
        "--rtp-stats-every",
        type=float,
        default=2.0,
        help="Segundos entre logs de métricas RTP",
    )
    p.add_argument("--auth-user", help="Usuario para autenticación Digest")
    p.add_argument("--auth-pass", help="Contraseña para autenticación Digest")
    p.add_argument("--auth-realm", help="Realm para autenticación Digest")
    p.add_argument(
        "--auth-username",
        help="Username para Digest si distinto del número de usuario",
    )
    p.add_argument(
        "--sdp-direction",
        choices=sorted(DIRECTION_SET),
        default="sendrecv",
        help="Dirección SDP preferida (sendrecv por defecto)",
    )
    p.add_argument(
        "--sip-header",
        action="append",
        dest="sip_headers",
        default=[],
        help="Cabecera SIP extra (repetible)",
    )
    p.add_argument(
        "--sip-headers-file",
        dest="sip_headers_file",
        help="Fichero con cabeceras SIP extra (una por línea)",
    )
    p.add_argument(
        "--extra-header",
        action="append",
        dest="sip_headers",
        help="(alias) Cabecera SIP extra",
    )
    p.add_argument(
        "--extra-headers-file",
        dest="sip_headers_file",
        help="(alias) Fichero con cabeceras extra",
    )
    p.add_argument(
        "--sdp-extra",
        action="append",
        dest="sdp_extra",
        default=[],
        help="Línea SDP extra (media). Repetible.",
    )
    p.add_argument(
        "--sdp-extras-file",
        dest="sdp_extras_file",
        help="Fichero con líneas SDP extra (media)",
    )
    p.add_argument(
        "--sdp-extra-session",
        action="append",
        dest="sdp_extra_session",
        default=[],
        help="Línea SDP extra a nivel de sesión",
    )
    # Load generator options
    p.add_argument("--load", action="store_true", help="Activa generador de llamadas")
    p.add_argument("--calls", type=int, default=1, help="Cuántas llamadas lanzar en total")
    p.add_argument("--rate", type=float, default=1.0, help="Llamadas por segundo")
    p.add_argument("--max-active", type=int, help="Máximo de llamadas simultáneas")
    p.add_argument("--from-number-start", help="Número From inicial")
    p.add_argument("--to-number-start", help="Número To inicial")
    p.add_argument("--number-step", type=int, default=1, help="Incremento por llamada")
    p.add_argument("--pad-width", type=int, default=0, help="Ancho con padding de ceros")
    p.add_argument("--to-domain-load", help="Dominio To para modo carga")
    p.add_argument("--from-domain-load", help="Dominio From para modo carga")
    p.add_argument("--to-uri-pattern", help="Plantilla de URI destino (sip:{num}@{host})")
    p.add_argument("--src-port-base", type=int, default=0, help="Puerto SIP origen base")
    p.add_argument("--src-port-step", type=int, default=10, help="Incremento puerto SIP")
    p.add_argument("--rtp-port-base", type=int, default=40000, help="Primer puerto RTP local")
    p.add_argument("--rtp-port-step", type=int, default=2, help="Incremento puerto RTP")

    # Compatibilidad con la CLI antigua: host [port]
    p.add_argument("host", nargs="?", help="Destino (compat)")
    p.add_argument("port", nargs="?", type=int, help="Puerto destino (compat)")
    args = p.parse_args()
    args.rtp_port_forced = any(a.startswith("--rtp-port") for a in sys.argv[1:])

    # Handle codec options
    if args.codec:
        args.codecs = args.codec
    codec_items = [c.strip().lower() for c in args.codecs.split(",") if c.strip()]
    codecs: list[tuple[int, str]] = []
    codec_names: list[str] = []
    used_pts: set[int] = set()
    next_dyn_pt = 96
    for item in codec_items:
        if item.isdigit():
            pt = int(item)
            name = CODEC_NAME_FROM_PT.get(pt, item.upper())
            if pt not in (0, 8) and not args.allow_unsupported_codecs:
                raise SystemExit(
                    f"Codec desconocido: {item} (usa --allow-unsupported-codecs para anunciarlo solo en SDP)"
                )
        elif item in PT_FROM_CODEC_NAME:
            pt = PT_FROM_CODEC_NAME[item]
            name = CODEC_NAME_FROM_PT[pt]
            if pt not in (0, 8) and not args.allow_unsupported_codecs:
                raise SystemExit(
                    f"Codec desconocido: {item} (usa --allow-unsupported-codecs para anunciarlo solo en SDP)"
                )
        elif args.allow_unsupported_codecs:
            while next_dyn_pt in used_pts:
                next_dyn_pt += 1
                if next_dyn_pt > 127:
                    raise SystemExit("Sin PT dinámicos disponibles")
            pt = next_dyn_pt
            next_dyn_pt += 1
            name = item.upper()
        else:
            raise SystemExit(
                f"Codec desconocido: {item} (usa --allow-unsupported-codecs para anunciarlo solo en SDP)"
            )
        codecs.append((pt, name))
        codec_names.append(item)
        used_pts.add(pt)
    args.codecs = codecs
    args.codec_names = codec_names
    if args.prefer:
        args.prefer = args.prefer.lower()
        if args.prefer not in codec_names:
            logger.warning("--prefer %s ignorado; no está en --codecs", args.prefer)
            args.prefer = None

    header_lines: list[str] = []
    if getattr(args, "sip_headers_file", None):
        with open(args.sip_headers_file, "r", encoding="utf-8") as f:
            header_lines.extend(line.rstrip("\n") for line in f)
    if getattr(args, "sip_headers", None):
        header_lines.extend(args.sip_headers)
    args.extra_headers = sanitize_extra_headers(header_lines, log=logger)

    sdp_media_lines: list[str] = []
    if getattr(args, "sdp_extras_file", None):
        with open(args.sdp_extras_file, "r", encoding="utf-8") as f:
            sdp_media_lines.extend(line.rstrip("\n") for line in f)
    sdp_media_lines.extend(getattr(args, "sdp_extra", []) or [])
    args.sdp_extras = [ln.strip() for ln in sdp_media_lines if ln.strip()]
    args.sdp_session_extras = [
        ln.strip() for ln in (getattr(args, "sdp_extra_session", []) or []) if ln.strip()
    ]

    args.sdp_direction = (args.sdp_direction or "sendrecv").lower()
    if args.sdp_direction not in DIRECTION_SET:
        logger.warning("Dirección SDP inválida %s; usando sendrecv", args.sdp_direction)
        args.sdp_direction = "sendrecv"

    # defaults for load generator
    if args.max_active is None:
        args.max_active = args.calls
    if args.to_domain_load is None:
        args.to_domain_load = args.to_domain or args.dst
    if args.from_domain_load is None:
        args.from_domain_load = args.from_domain or args.bind_ip

    return args


def make_per_call_args(
    base,
    i,
    fixed_numbers=False,
    num_step=1,
    rtp_port_base=None,
    rtp_port_step=2,
):
    from types import SimpleNamespace

    a = SimpleNamespace(**vars(base))  # copia superficial

    # Numeración
    if fixed_numbers:
        a.from_user = base.from_user
        a.to_user = base.to_user
    else:
        if hasattr(base, "from_user_start"):
            a.from_user = str(int(base.from_user_start) + i * num_step).zfill(
                int(getattr(base, "pad_width", 0) or 0)
            )
        if hasattr(base, "to_user_start"):
            a.to_user = str(int(base.to_user_start) + i * num_step).zfill(
                int(getattr(base, "pad_width", 0) or 0)
            )

    # Puertos
    if rtp_port_base:
        a.rtp_port = int(rtp_port_base) + i * int(rtp_port_step or 2)

    # Defaults robustos
    if not hasattr(a, "extra_headers"):
        a.extra_headers = ""
    if not hasattr(a, "rtp_send_silence"):
        a.rtp_send_silence = False

    # Reconstruye URIs y cabeceras
    a.from_uri, a.to_uri, a.extra_headers_list = build_identities(a)
    return a


def run_load_generator(args, sip_manager, sip_transport: SipTransport, stats_cb=None):
    """Generate many calls with controlled rate and incremental parameters.

    Parameters
    ----------
    args: Namespace
        Argumentos de configuración.
    sip_manager: SIPManager
        Gestor SIP para realizar las llamadas.
    stats_cb: callable | None
        Si se proporciona, se invoca periódicamente con una copia de los
        contadores actuales.
    """
    import threading
    from datetime import datetime, UTC
    import time
    import errno

    counters = {
        "launched": 0,
        "established": 0,
        "failed_4xx": 0,
        "failed_5xx_6xx": 0,
        "canceled": 0,
        "remote_bye": 0,
        "max_time_bye": 0,
        "aborted": 0,
    }
    active = set()
    lock = threading.Lock()

    if not args.to_uri_pattern and not args.to_number_start:
        raise SystemExit("--to-number-start requerido si no se usa --to-uri-pattern")

    dst = args.dst or args.host
    dport = args.dst_port if args.dst else (args.port or 5060)

    try:
        pad_width = int(getattr(args, "pad_width", 0) or 0)
    except (TypeError, ValueError):
        pad_width = 0
    try:
        step = int(getattr(args, "number_step", 1) or 1)
    except (TypeError, ValueError):
        step = 1
    if step < 1:
        step = 1
    args.pad_width = pad_width
    args.number_step = step
    fixed_numbers = bool(getattr(args, "use_fixed_numbers", False))
    if not fixed_numbers:
        fixed_numbers = bool(getattr(args, "fixed_numbers", False))

    to_start = int(args.to_number_start or 0)
    from_start = int(args.from_number_start or 0)
    args.from_user_start = args.from_number_start
    args.to_user_start = args.to_number_start
    args.from_user = getattr(args, "from_user", None) or getattr(args, "from_number", None)
    args.to_user = getattr(args, "to_user", None) or getattr(args, "to_number", None)
    args.from_domain = getattr(args, "from_domain_load", None)
    args.to_domain = getattr(args, "to_domain_load", None)

    base_extra_headers = _parse_extra_headers(
        getattr(args, "extra_headers_list", None)
        or getattr(args, "extra_headers", None),
        log=logger,
    )
    if not base_extra_headers:
        base_extra_headers = _parse_extra_headers(
            getattr(args, "extra_headers_text", None),
            log=logger,
        )

    def _coerce_str_list(value):
        if value is None:
            return []
        if isinstance(value, str):
            raw_items = value.replace("\r", "").split("\n")
        else:
            try:
                raw_items = list(value)
            except TypeError:
                return []
        cleaned: list[str] = []
        for item in raw_items:
            if item is None:
                continue
            text = str(item).strip()
            if text:
                cleaned.append(text)
        return cleaned

    sdp_media_extras = _coerce_str_list(getattr(args, "sdp_extras", []))
    sdp_session_extras = _coerce_str_list(getattr(args, "sdp_session_extras", []))
    sdp_direction = (getattr(args, "sdp_direction", "sendrecv") or "sendrecv").lower()
    if sdp_direction not in DIRECTION_SET:
        logger.warning("Dirección SDP inválida %s; usando sendrecv", sdp_direction)
        sdp_direction = "sendrecv"

    args.extra_headers = base_extra_headers
    args.sdp_extras = sdp_media_extras
    args.sdp_session_extras = sdp_session_extras
    args.sdp_direction = sdp_direction

    def format_num(num):
        return str(num).zfill(pad_width) if pad_width > 0 else str(num)

    def _resolve_local_ip(sock):
        if args.bind_ip and args.bind_ip != "0.0.0.0":
            return args.bind_ip
        local_ip = sock.getsockname()[0]
        if local_ip == "0.0.0.0":
            try:
                sock.connect((dst, dport))
                local_ip = sock.getsockname()[0]
                sock.connect(("0.0.0.0", 0))
            except Exception:
                local_ip = sock.getsockname()[0]
        return local_ip

    sip_ip = sip_transport.bind_ip
    sip_port = sip_transport.src_port

    call_queues: dict[str, queue.Queue] = {}
    rx_stop = threading.Event()

    def rx_loop():
        while not rx_stop.is_set():
            try:
                data, addr = sip_transport.recvfrom()
            except socket.timeout:
                continue
            except OSError:
                break
            _, headers = parse_headers(data)
            call_id = headers.get("call-id")
            if not call_id:
                continue
            with lock:
                q = call_queues.get(call_id)
            if q:
                q.put((data, addr))

    def worker(i):
        nonlocal counters
        local_ip = _resolve_local_ip(sip_transport.sock)
        call_args = make_per_call_args(
            args,
            i,
            fixed_numbers=fixed_numbers,
            num_step=step,
            rtp_port_base=args.rtp_port_base,
            rtp_port_step=args.rtp_port_step,
        )
        if fixed_numbers:
            num_to = format_num(to_start)
            num_from = format_num(from_start) if args.from_number_start else None
        else:
            num_to = format_num(to_start + i * step)
            num_from = (
                format_num(from_start + i * step) if args.from_number_start else None
            )
        call_args.to_user = num_to
        if num_from is not None:
            call_args.from_user = num_from
        if args.to_uri_pattern:
            call_args.to_uri = args.to_uri_pattern.format(
                num=call_args.to_user,
                host=args.to_domain_load,
            )
        call_args.from_uri, call_args.to_uri, call_args.extra_headers_list = build_identities(
            call_args
        )
        call_args.sdp_mode = getattr(args, "sdp_mode", None) or getattr(
            args, "sdp_direction", "sendrecv"
        )

        from_uri = _norm_sip_uri(
            call_args.from_user,
            call_args.from_domain,
            getattr(call_args, "from_uri", None),
        )
        final_to_uri = _norm_sip_uri(
            call_args.to_user,
            call_args.to_domain,
            getattr(call_args, "to_uri", None),
        )
        try:
            from_uri = _require(from_uri, "from_uri", logger)
            final_to_uri = _require(final_to_uri, "to_uri", logger)
        except ValueError:
            with lock:
                counters["aborted"] += 1
                active.discard(threading.current_thread())
            return

        rtp_port = getattr(call_args, "rtp_port", args.rtp_port_base)
        if rtp_port % 2:
            rtp_port += 1
        ts = datetime.now(UTC).isoformat()
        call_args.rtp_port = rtp_port
        send_silence = bool(
            getattr(args, "rtp_send_silence", False)
            or getattr(args, "rtp_always_silence", False)
        )
        call_args.rtp_send_silence = send_silence
        call_args.codecs = args.codecs
        call_args.extra_headers_list = call_args.extra_headers_list or base_extra_headers

        call_id = f"{uuid.uuid4()}"
        call_id_key = call_id
        try:
            rx_queue: queue.Queue = queue.Queue()
            with lock:
                call_queues[call_id_key] = rx_queue
            call_id, result, setup_ms, dialog = generator_call_worker(
                sip_transport,
                sip_ip,
                sip_port,
                local_ip,
                (dst, int(dport)),
                args,
                call_args,
                call_id_key,
                rx_queue,
                stats_cb=stats_cb,
            )
        except OSError as e:
            call_id = call_id_key
            result = f"error({getattr(e, 'errno', 'socket')})"
            setup_ms = 0
        except Exception as e:
            logger.error(f"LOAD: error en llamada: {e}")
            with lock:
                counters["aborted"] += 1
                active.discard(threading.current_thread())
            return
        finally:
            with lock:
                call_queues.pop(call_id_key, None)

        write_csv_row(
            "calls_summary.csv",
            [ts, call_id, from_uri, final_to_uri, sip_port, rtp_port, setup_ms, result],
            [
                "ts_start",
                "call_id",
                "from_uri",
                "to_uri",
                "src_port",
                "rtp_port",
                "setup_ms",
                "result",
            ],
        )
        with lock:
            if result in ("answered", "remote-bye", "max-time-bye", "canceled-after-200"):
                counters["established"] += 1
            if result.startswith("busy") or result.startswith("rejected(4"):
                counters["failed_4xx"] += 1
            if result.startswith("rejected(5") or result.startswith("rejected(6"):
                counters["failed_5xx_6xx"] += 1
            if result.startswith("canceled"):
                counters["canceled"] += 1
            if result == "remote-bye":
                counters["remote_bye"] += 1
            if result == "max-time-bye":
                counters["max_time_bye"] += 1
            if result == "aborted":
                counters["aborted"] += 1
            active.discard(threading.current_thread())

    stop = threading.Event()

    def printer():
        while not stop.is_set():
            with lock:
                snapshot = counters.copy()
                snapshot["active"] = len(active)
                line = (
                    f"[LOAD] active={snapshot['active']} launched={snapshot['launched']} "
                    f"established={snapshot['established']} 4xx={snapshot['failed_4xx']} "
                    f"5xx={snapshot['failed_5xx_6xx']} canceled={snapshot['canceled']} "
                    f"remote_bye={snapshot['remote_bye']}"
                )
            if stats_cb:
                try:
                    stats_cb(snapshot)
                except Exception:
                    pass
            print(line)
            if stop.wait(2):
                break

    rx_thread = threading.Thread(target=rx_loop, daemon=True)
    rx_thread.start()
    printer_t = threading.Thread(target=printer, daemon=True)
    printer_t.start()

    start = time.monotonic()
    threads: list[threading.Thread] = []
    try:
        for i in range(args.calls):
            while True:
                with lock:
                    if len(active) < args.max_active:
                        break
                time.sleep(0.05)
            target_time = start + i * (1 / args.rate if args.rate > 0 else 0)
            now = time.monotonic()
            if target_time > now:
                time.sleep(target_time - now)
            t = threading.Thread(target=worker, args=(i,))
            with lock:
                counters["launched"] += 1
                active.add(t)
            t.start()
            threads.append(t)
    except KeyboardInterrupt:
        print("Interrumpido, esperando a las llamadas activas...")

    for t in threads:
        t.join()
    stop.set()
    printer_t.join()
    rx_stop.set()
    rx_thread.join(timeout=1.0)
    if stats_cb:
        with lock:
            final = counters.copy()
            final["active"] = len(active)
        try:
            stats_cb(final)
        except Exception:
            pass
    return counters

def main():
    args = parse_args()

    if args.options_monitor:
        if not args.dst:
            raise SystemExit("Falta destino: usa --dst 10.0.0.1")
        if not args.single_socket:
            raise SystemExit("--options-monitor requiere --single-socket")
        reac = Reactor(args.bind_ip or "0.0.0.0", args.src_port)
        if args.reply_options:
            register_options_responder(reac)
        mon = OptionsMonitor(
            reac,
            dst_host=args.dst,
            dst_port=args.dst_port,
            interval=args.interval,
            timeout=args.timeout,
            cseq_start=args.cseq_start,
        )
        mon.start()
        try:
            reac.run()
        except KeyboardInterrupt:
            pass
        finally:
            mon.stop()
            reac.stop()
        return

    if getattr(args, "gui", False):
        from gui_tk import main as gui_main

        gui_main(args)
        return

    if getattr(args, "tui", False):
        from tui import run

        run(args)
        return

    if args.load:
        if not (args.dst or args.host):
            raise SystemExit("Falta destino: usa --dst 10.0.0.1")
        sip_transport = get_sip_transport(args.bind_ip or "0.0.0.0", args.src_port)
        sm = SIPManager(protocol=args.protocol, transport=sip_transport)
        run_load_generator(args, sm, sip_transport)
        return

    if args.uas and not args.service:
        args.service = True
    if args.uas:
        args.uas_rtp_port = args.rtp_port

    if args.reply_options and not args.service:
        raise SystemExit("--reply-options requiere --service")

    if args.invite and args.service:
        raise SystemExit("--invite incompatible con --service")

    dst = args.dst or args.host
    dport = args.dst_port if args.dst else (args.port or 5060)

    csv_path = "dimitri_stats.csv"
    header = ["ts_iso", "dst", "dst_port", "protocol", "status_code", "reason", "rtt_ms"]

    if args.invite:
        if not dst:
            raise SystemExit("Falta destino: usa --dst 10.0.0.1")
        if not (args.to_uri or args.to_number or args.to):
            raise SystemExit("Falta --to-number o --to-uri")
        to_uri = args.to_uri
        if not to_uri and args.to:
            to_uri = args.to if args.to.startswith("sip:") else f"sip:{args.to}"
        sip_transport = get_sip_transport(args.bind_ip or "0.0.0.0", args.src_port)
        sm = SIPManager(protocol=args.protocol, transport=sip_transport)
        extra_headers = (
            getattr(args, "extra_headers_list", None)
            or getattr(args, "extra_headers", [])
            or []
        )
        try:
            call_id, result, setup_ms, talk_s = sm.place_call(
                dst_host=dst,
                dst_port=dport,
                from_number=args.from_number or args.from_user,
                from_domain=args.from_domain,
                from_display=args.from_display,
                to_number=args.to_number,
                to_domain=args.to_domain,
                from_uri=args.from_uri,
                to_uri=to_uri,
                pai=args.pai,
                use_pai=args.use_pai,
                use_pai_asserted=args.use_pai_asserted,
                auth_user=args.auth_user,
                auth_pass=args.auth_pass,
                auth_realm=args.auth_realm,
                auth_username=args.auth_username,
                bind_ip=args.bind_ip,
                bind_port=args.src_port,
                timeout=args.timeout,
                cseq_start=args.cseq_start,
                ring_timeout=args.ring_timeout,
                talk_time=args.talk_time,
                wait_bye=args.wait_bye,
                max_call_time=args.max_call_time,
                codecs=args.codecs,
                rtp_port=args.rtp_port,
                rtp_port_forced=args.rtp_port_forced,
                rtcp=args.rtcp,
                tone_hz=args.rtp_tone,
                send_silence=(
                    _get_flag(args, "rtp_send_silence")
                    or _get_flag(args, "rtp_always_silence")
                ),
                symmetric=args.symmetric_rtp,
                save_wav=args.rtp_save_wav,
                stats_interval=args.rtp_stats_every,
                extra_headers=extra_headers,
                sdp_direction=args.sdp_direction,
                sdp_media_extras=args.sdp_extras,
                sdp_session_extras=args.sdp_session_extras,
            )
        except KeyboardInterrupt:
            raise SystemExit(130)
        except OSError as e:
            if e.errno == errno.EADDRINUSE:
                logger.error(
                    f"No se pudo bindear UDP en {args.bind_ip or '0.0.0.0'}:{args.src_port}: {e}"
                )
            else:
                logger.error(
                    f"Error de red enviando/recibiendo UDP hacia {dst}:{dport}: {e}"
                )
            raise SystemExit(1)
        ts = datetime.now(UTC).isoformat()
        header = ["ts_iso", "call_id", "to", "result", "setup_ms", "talk_s"]
        write_csv_row(
            "dimitri_calls.csv", [ts, call_id, to_uri, result, setup_ms, talk_s], header
        )
        print(f"Llamada {result} (setup={setup_ms} ms)")
        return

    if args.service:
        if not dst and not args.reply_options:
            raise SystemExit("En modo servicio se requiere --dst o --reply-options")

        try:
            sip_transport = get_sip_transport(args.bind_ip or "0.0.0.0", args.src_port)
            sock = sip_transport.sock
        except OSError as e:
            logger.error(
                f"No se pudo bindear UDP en {args.bind_ip or '0.0.0.0'}:{args.src_port}: {e}"
            )
            raise SystemExit(1)

        local_ip = args.bind_ip or sock.getsockname()[0]
        local_port = sip_transport.src_port
        sip_ip = sip_transport.bind_ip
        local_pts = [pt for pt, _ in args.codecs if pt in (0, 8)]
        if not local_pts:
            local_pts = [0, 8]
        first_pt = local_pts[0]
        contact_ip = sip_ip
        sdp_ip = args.advertised_ip or local_ip
        user = "dimitri"
        tag_local = uuid.uuid4().hex[:8]
        pending = []  # call_id -> send_time
        cseq = args.cseq_start
        next_send = time.time()
        dialogs: dict = {}
        events: list = []

        def schedule(key, typ, delay):
            t = time.time() + delay
            for e in events:
                if e["key"] == key and e["type"] == typ:
                    return
            events.append({"time": t, "type": typ, "key": key})

        def cancel_events(key, types=None):
            events[:] = [
                e for e in events if not (e["key"] == key and (types is None or e["type"] in types))
            ]

        try:
            while True:
                now = time.time()
                next_timeout = (
                    min(p["send_time"] + args.timeout for p in pending)
                    if pending
                    else None
                )
                next_event = min(e["time"] for e in events) if events else None
                wait_send = max(0, next_send - now) if dst else None
                wait_to = max(0, next_timeout - now) if next_timeout else None
                wait_evt = max(0, next_event - now) if next_event else None
                timeout = None
                for w in (wait_send, wait_to, wait_evt):
                    if w is None:
                        continue
                    timeout = w if timeout is None else min(timeout, w)

                r, _, _ = select.select([sock], [], [], timeout)
                now = time.time()

                if r:
                    data, addr = sock.recvfrom(4096)
                    start, headers = parse_headers(data)
                    if start.startswith("SIP/2.0"):
                        call_id = headers.get("call-id")
                        code, reason = status_from_response(data)
                        cseq_hdr = headers.get("cseq", "")
                        if cseq_hdr.endswith("BYE"):
                            for key, d in list(dialogs.items()):
                                if d["call_id"] == call_id and d.get("state") == "bye_sent":
                                    cancel_events(key)
                                    dialogs.pop(key, None)
                                    break
                        else:
                            for p in list(pending):
                                if p["call_id"] == call_id:
                                    rtt_ms = int((now - p["send_time"]) * 1000)
                                    ts = datetime.now(UTC).isoformat()
                                    write_csv_row(
                                        csv_path,
                                        [
                                            ts,
                                            p["dst"],
                                            p["dport"],
                                            args.protocol,
                                            code,
                                            reason,
                                            rtt_ms,
                                        ],
                                        header,
                                    )
                                    pending.remove(p)
                                    break
                    elif start.startswith("OPTIONS sip:") and args.reply_options:
                        try:
                            via = headers["via"]
                            fr = headers["from"]
                            to = headers["to"]
                            call_id = headers["call-id"]
                            cseq_hdr = headers["cseq"]
                        except KeyError:
                            logger.debug(
                                "OPTIONS recibido incompleto de %s:%s", addr[0], addr[1]
                            )
                        else:
                            if "tag=" not in to.lower():
                                to = f"{to};tag={tag_local}"
                            contact_ip_resp = sip_ip
                            resp = (
                                "SIP/2.0 200 OK\r\n"
                                f"Via: {via}\r\n"
                                f"From: {fr}\r\n"
                                f"To: {to}\r\n"
                                f"Call-ID: {call_id}\r\n"
                                f"CSeq: {cseq_hdr}\r\n"
                                f"Contact: <sip:{user}@{contact_ip_resp}:{local_port}>\r\n"
                                "User-Agent: Dimitri-4000/0.1\r\n"
                                "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE\r\n"
                                "Accept: application/sdp\r\n"
                                "Content-Length: 0\r\n\r\n"
                            ).encode()
                            sock.sendto(resp, addr)
                            cseq_num = cseq_hdr.split()[0] if cseq_hdr else ""
                            logger.info(
                                f"Responded 200 OK to OPTIONS from {addr[0]}:{addr[1]} cid={call_id} cseq={cseq_num}"
                            )
                    elif args.uas and start.startswith("INVITE "):
                        try:
                            via = headers["via"]
                            fr = headers["from"]
                            to = headers["to"]
                            call_id = headers["call-id"]
                            cseq_hdr = headers["cseq"]
                        except KeyError:
                            logger.debug("INVITE incompleto de %s:%s", addr[0], addr[1])
                        else:
                            remote_tag = None
                            if "tag=" in fr.lower():
                                remote_tag = fr.split("tag=")[1].split(";", 1)[0]
                            local_tag = uuid.uuid4().hex[:8]
                            key = (call_id, remote_tag)
                            peer_uri = headers.get("contact")
                            if peer_uri and "<" in peer_uri and ">" in peer_uri:
                                peer_uri = peer_uri.split("<", 1)[1].split(">", 1)[0]
                            else:
                                peer_uri = fr.split("<", 1)[1].split(">", 1)[0]
                            body = b""
                            if b"\r\n\r\n" in data:
                                body = data.split(b"\r\n\r\n", 1)[1]
                            sdp_info = parse_sdp(body)
                            rip = sdp_info.get("ip")
                            rport = sdp_info.get("audio_port")
                            remote_pts = sdp_info.get("pts") or []
                            offer_dir = sdp_info.get("direction", "sendrecv") or "sendrecv"
                            if offer_dir not in DIRECTION_SET:
                                offer_dir = "sendrecv"
                            logger.info(
                                "Offer SDP PTs=%s; supported locally=[0,8]",
                                remote_pts,
                            )
                            chosen_pt = None
                            if remote_pts:
                                common = [pt for pt in remote_pts if pt in local_pts]
                                if not common:
                                    headers488 = {
                                        "Via": via,
                                        "From": fr,
                                        "To": to,
                                        "Call-ID": call_id,
                                        "CSeq": cseq_hdr,
                                    }
                                    sock.sendto(
                                        build_response(488, "Not Acceptable Here", headers488),
                                        addr,
                                    )
                                    continue
                                if args.prefer:
                                    prefer_pt = PT_FROM_CODEC_NAME[args.prefer]
                                    if prefer_pt in common:
                                        chosen_pt = prefer_pt
                                if chosen_pt is None:
                                    for pt in local_pts:
                                        if pt in common:
                                            chosen_pt = pt
                                            break
                            else:
                                chosen_pt = first_pt
                            dialog = {
                                "peer_addr": addr,
                                "from_uri": fr,
                                "to_uri": to.split(";", 1)[0],
                                "call_id": call_id,
                                "remote_tag": remote_tag,
                                "local_tag": local_tag,
                                "their_cseq_invite": cseq_hdr.split()[0],
                                "our_next_cseq": 1,
                                "peer_uri": peer_uri,
                                "start_ts": now,
                                "state": "invited",
                                "via": via,
                                "cseq_hdr": cseq_hdr,
                                "local_ip": contact_ip,
                                "local_port": local_port,
                                "remote_rtp": (rip, rport),
                                "pt": chosen_pt,
                                "offer_dir": offer_dir,
                            }
                            dialogs[key] = dialog
                            resp = build_response(
                                100,
                                "Trying",
                                {
                                    "Via": via,
                                    "From": fr,
                                    "To": to,
                                    "Call-ID": call_id,
                                    "CSeq": cseq_hdr,
                                },
                            )
                            sock.sendto(resp, addr)
                            schedule(key, "ring", args.uas_ring_delay)
                            schedule(key, "answer", args.uas_answer_after)
                    elif args.uas and start.startswith("CANCEL "):
                        try:
                            via = headers["via"]
                            fr = headers["from"]
                            to = headers["to"]
                            call_id = headers["call-id"]
                            cseq_hdr = headers["cseq"]
                        except KeyError:
                            logger.debug("CANCEL incompleto de %s:%s", addr[0], addr[1])
                        else:
                            remote_tag = None
                            if "tag=" in fr.lower():
                                remote_tag = fr.split("tag=")[1].split(";", 1)[0]
                            key = (call_id, remote_tag)
                            dialog = dialogs.get(key)
                            to_resp = to
                            if dialog:
                                to_resp = f"{dialog['to_uri']};tag={dialog['local_tag']}"
                                cancel_events(key)
                                dialog["state"] = "cancelled"
                            resp = build_response(
                                200,
                                "OK",
                                {
                                    "Via": via,
                                    "From": fr,
                                    "To": to_resp,
                                    "Call-ID": call_id,
                                    "CSeq": cseq_hdr,
                                },
                            )
                            sock.sendto(resp, addr)
                            if dialog:
                                resp487 = build_response(
                                    487,
                                    "Request Terminated",
                                    {
                                        "Via": dialog["via"],
                                        "From": fr,
                                        "To": to_resp,
                                        "Call-ID": call_id,
                                        "CSeq": dialog["cseq_hdr"],
                                    },
                                )
                                sock.sendto(resp487, addr)
                                schedule(key, "del", 5)
                    elif args.uas and start.startswith("ACK "):
                        try:
                            fr = headers["from"]
                            to = headers["to"]
                            call_id = headers["call-id"]
                            cseq_hdr = headers["cseq"]
                        except KeyError:
                            pass
                        else:
                            remote_tag = None
                            if "tag=" in fr.lower():
                                remote_tag = fr.split("tag=")[1].split(";", 1)[0]
                            key = (call_id, remote_tag)
                            dialog = dialogs.get(key)
                            if dialog:
                                local_tag = None
                                if "tag=" in to.lower():
                                    local_tag = to.split("tag=")[1].split(";", 1)[0]
                                cseq_num = cseq_hdr.split()[0] if cseq_hdr else ""
                                if (
                                    local_tag == dialog["local_tag"]
                                    and cseq_num == dialog["their_cseq_invite"]
                                ):
                                    if dialog.get("state") == "cancelled":
                                        cancel_events(key)
                                        dialogs.pop(key, None)
                                    elif dialog.get("state") == "answered":
                                        dialog["state"] = "established"
                                        cancel_events(key, ["200_retx", "timer_m"])
                                        body = b""
                                        if b"\r\n\r\n" in data:
                                            body = data.split(b"\r\n\r\n", 1)[1]
                                        if body:
                                            sdp_info = parse_sdp(body)
                                            rip = sdp_info.get("ip")
                                            rport = sdp_info.get("audio_port")
                                            dialog["remote_rtp"] = (rip, rport)
                                        else:
                                            rip, rport = dialog.get("remote_rtp", (None, None))
                                        pt_use = dialog.get("pt", first_pt)
                                        sym = args.symmetric_rtp or not (rip and rport)
                                        rtp = RtpSession(
                                            dialog["local_ip"],
                                            args.rtp_port,
                                            pt_use,
                                            symmetric=sym,
                                            save_wav=args.rtp_save_wav,
                                            forced=args.rtp_port_forced,
                                        )
                                        rtp.rtcp = args.rtcp
                                        rtp.tone_hz = args.rtp_tone
                                        rtp.send_silence = (
                                            (
                                                _get_flag(args, "rtp_send_silence")
                                                or _get_flag(args, "rtp_always_silence")
                                            )
                                            and not args.rtp_tone
                                        )
                                        rtp.stats_interval = args.rtp_stats_every
                                        if "ans_send" in dialog:
                                            rtp.set_sending(bool(dialog["ans_send"]))
                                        if "ans_recv" in dialog:
                                            rtp.set_receiving(bool(dialog["ans_recv"]))
                                        rtp.start(rip, rport)
                                        dialog["rtp"] = rtp
                                        if args.uas_talk_time > 0:
                                            schedule(key, "bye", args.uas_talk_time)
                    elif args.uas and start.startswith("BYE "):
                        try:
                            via = headers["via"]
                            fr = headers["from"]
                            to = headers["to"]
                            call_id = headers["call-id"]
                            cseq_hdr = headers["cseq"]
                        except KeyError:
                            logger.debug("BYE incompleto de %s:%s", addr[0], addr[1])
                        else:
                            remote_tag = None
                            if "tag=" in fr.lower():
                                remote_tag = fr.split("tag=")[1].split(";", 1)[0]
                            key = (call_id, remote_tag)
                            dialog = dialogs.get(key)
                            to_resp = to
                            if dialog:
                                to_resp = f"{dialog['to_uri']};tag={dialog['local_tag']}"
                            resp = build_response(
                                200,
                                "OK",
                                {
                                    "Via": via,
                                    "From": fr,
                                    "To": to_resp,
                                    "Call-ID": call_id,
                                    "CSeq": cseq_hdr,
                                },
                            )
                            sock.sendto(resp, addr)
                            if dialog and dialog.get("rtp"):
                                dialog["rtp"].stop()
                            cancel_events(key)
                            dialogs.pop(key, None)
                    else:
                        logger.debug(
                            "Datagrama ignorado de %s:%s", addr[0], addr[1]
                        )
                else:
                    for p in list(pending):
                        if now - p["send_time"] >= args.timeout:
                            ts = datetime.now(UTC).isoformat()
                            write_csv_row(
                                csv_path,
                                [
                                    ts,
                                    p["dst"],
                                    p["dport"],
                                    args.protocol,
                                    "",
                                    "timeout",
                                    "",
                                ],
                                header,
                            )
                            pending.remove(p)

                # ejecutar eventos programados
                for ev in list(events):
                    if now >= ev["time"]:
                        try:
                            events.remove(ev)
                        except ValueError:
                            continue
                        key = ev["key"]
                        dialog = dialogs.get(key)
                        if not dialog:
                            continue
                        etype = ev["type"]
                        if etype == "ring":
                            headers = {
                                "Via": dialog["via"],
                                "From": dialog["from_uri"],
                                "To": f"{dialog['to_uri']};tag={dialog['local_tag']}",
                                "Call-ID": dialog["call_id"],
                                "CSeq": dialog["cseq_hdr"],
                            }
                            sock.sendto(
                                build_response(180, "Ringing", headers), dialog["peer_addr"]
                            )
                            dialog["state"] = "ringing"
                        elif etype == "answer":
                            headers = {
                                "Via": dialog["via"],
                                "From": dialog["from_uri"],
                                "To": f"{dialog['to_uri']};tag={dialog['local_tag']}",
                                "Call-ID": dialog["call_id"],
                                "CSeq": dialog["cseq_hdr"],
                                "Contact": f"<sip:{user}@{contact_ip}:{local_port}>",
                                "Content-Type": "application/sdp",
                            }
                            offer_dir = dialog.get("offer_dir", "sendrecv") or "sendrecv"
                            if offer_dir not in DIRECTION_SET:
                                offer_dir = "sendrecv"
                            answer_dir = intersect_answer(offer_dir, args.sdp_direction)
                            ans_send, ans_recv = direction_to_flags(answer_dir)
                            offer_send, offer_recv = direction_to_flags(offer_dir)
                            remote_effective = flags_to_direction(
                                offer_send and ans_recv, offer_recv and ans_send
                            )
                            logger.info(
                                "SDP negotiated dir: offer=%s, answer=%s -> effective: %s local / %s remote",
                                offer_dir,
                                answer_dir,
                                answer_dir,
                                remote_effective,
                            )
                            sdp = build_sdp(
                                sdp_ip,
                                args.rtp_port,
                                [
                                    (
                                        dialog["pt"],
                                        CODEC_NAME_FROM_PT.get(
                                            dialog["pt"], str(dialog["pt"])
                                        ),
                                    )
                                ],
                                session_extras=args.sdp_session_extras,
                                media_extras=args.sdp_extras,
                                direction=answer_dir,
                            )
                            dialog["answer_dir"] = answer_dir
                            dialog["ans_send"] = ans_send
                            dialog["ans_recv"] = ans_recv
                            dialog["remote_direction"] = remote_effective
                            sock.sendto(
                                build_response(200, "OK", headers, sdp), dialog["peer_addr"]
                            )
                            codec_name = CODEC_NAME_FROM_PT.get(dialog["pt"], str(dialog["pt"]))
                            logger.info(
                                f"Negotiated codec: {codec_name} (PT={dialog['pt']})"
                            )
                            dialog["state"] = "answered"
                            dialog["retx"] = 0.5
                            schedule(key, "200_retx", dialog["retx"])
                            schedule(key, "timer_m", 0.5 * 64)
                        elif etype == "200_retx":
                            if dialog.get("state") == "answered":
                                headers = {
                                    "Via": dialog["via"],
                                    "From": dialog["from_uri"],
                                    "To": f"{dialog['to_uri']};tag={dialog['local_tag']}",
                                    "Call-ID": dialog["call_id"],
                                    "CSeq": dialog["cseq_hdr"],
                                "Contact": f"<sip:{user}@{contact_ip}:{local_port}>",
                                    "Content-Type": "application/sdp",
                                }
                                answer_dir = dialog.get("answer_dir", args.sdp_direction)
                                sdp = build_sdp(
                                    sdp_ip,
                                    args.rtp_port,
                                    [
                                        (
                                            dialog["pt"],
                                            CODEC_NAME_FROM_PT.get(
                                                dialog["pt"], str(dialog["pt"])
                                            ),
                                        )
                                    ],
                                    session_extras=args.sdp_session_extras,
                                    media_extras=args.sdp_extras,
                                    direction=answer_dir,
                                )
                                sock.sendto(
                                    build_response(200, "OK", headers, sdp),
                                    dialog["peer_addr"],
                                )
                                dialog["retx"] = min(dialog["retx"] * 2, 4)
                                schedule(key, "200_retx", dialog["retx"])
                        elif etype == "timer_m":
                            dialogs.pop(key, None)
                            cancel_events(key)
                        elif etype == "bye":
                            bye = build_bye(dialog)
                            sock.sendto(bye, dialog["peer_addr"])
                            dialog["state"] = "bye_sent"
                            if dialog.get("rtp"):
                                dialog["rtp"].stop()
                            schedule(key, "del", 5)
                        elif etype == "del":
                            if dialog.get("rtp"):
                                dialog["rtp"].stop()
                            dialogs.pop(key, None)
                            cancel_events(key)

                if dst and now >= next_send:
                    if args.bind_ip:
                        local_ip = args.bind_ip
                    else:
                        tmp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        try:
                            tmp.connect((dst, dport))
                            local_ip = tmp.getsockname()[0]
                        except OSError:
                            local_ip = sock.getsockname()[0]
                        finally:
                            tmp.close()
                    call_id, payload = build_options(
                        dst, local_ip, local_port, user, cseq
                    )
                    logger.info(
                        f"Enviando OPTIONS (CSeq={cseq}) a {dst}:{dport} sent-by={local_ip}:{local_port}"
                    )
                    try:
                        sock.sendto(payload, (dst, dport))
                    except OSError as e:
                        logger.error(f"Error al enviar OPTIONS: {e}")
                    else:
                        pending.append(
                            {
                                "call_id": call_id,
                                "send_time": now,
                                "dst": dst,
                                "dport": dport,
                            }
                        )
                    cseq += 1
                    next_send = now + args.interval

        except KeyboardInterrupt:
            logger.info("Saliendo por Ctrl+C")
        finally:
            sock.close()

    else:
        if not dst:
            raise SystemExit(
                "Falta destino: usa --dst 10.0.0.1 o positional 'host'."
            )

        sm = SIPManager(protocol=args.protocol)
        ok = other = to = 0
        for i in range(args.count):
            cseq = args.cseq_start + i
            logger.info(f"Enviando OPTIONS (CSeq={cseq}) a {dst}:{dport}")
            try:
                code, reason, rtt_ms = sm.send_request(
                    dst_host=dst,
                    dst_port=dport,
                    timeout=args.timeout,
                    bind_ip=args.bind_ip,
                    bind_port=args.src_port,
                    cseq=cseq,
                    extra_headers=(
                        getattr(args, "extra_headers_list", None)
                        or getattr(args, "extra_headers", [])
                        or []
                    ),
                )
            except OSError as e:
                logger.error(
                    f"No se pudo abrir socket UDP en puerto {args.src_port}: {e}"
                )
                raise SystemExit(1)

            ts = datetime.now(UTC).isoformat()
            if code is None:
                print(f"[{i+1}/{args.count}] Timeout")
                to += 1
                write_csv_row(
                    csv_path, [ts, dst, dport, args.protocol, "", "timeout", ""], header
                )
            else:
                print(f"[{i+1}/{args.count}] {code} {reason} {rtt_ms} ms")
                if code == 200:
                    ok += 1
                else:
                    other += 1
                write_csv_row(
                    csv_path,
                    [ts, dst, dport, args.protocol, code, reason, rtt_ms],
                    header,
                )

            if i + 1 < args.count:
                time.sleep(args.interval)

        print(f"Resumen: 200={ok} otros={other} timeouts={to}")


if __name__ == "__main__":
    main()
