import argparse
import csv
import os
import select
import socket
import time
import uuid
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
    build_sdp,
    build_bye,
    parse_headers,
    status_from_response,
)


def write_csv_row(path, row, header=None):
    new_file = not os.path.exists(path)
    with open(path, "a", newline="") as f:
        w = csv.writer(f)
        if new_file and header:
            w.writerow(header)
        w.writerow(row)


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
    p.add_argument("--uas", action="store_true", help="Habilita servidor SIP UAS")
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
        "--uas-codec",
        choices=["pcmu", "pcma"],
        default="pcmu",
        help="Codec SDP para UAS",
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
    p.add_argument("--codec", choices=["pcmu", "pcma"], default="pcmu", help="Codec SDP")
    p.add_argument("--rtp-port", type=int, default=40000, help="Puerto RTP local")
    # Compatibilidad con la CLI antigua: host [port]
    p.add_argument("host", nargs="?", help="Destino (compat)")
    p.add_argument("port", nargs="?", type=int, help="Puerto destino (compat)")
    return p.parse_args()


def main():
    args = parse_args()

    if args.uas and not args.service:
        args.service = True

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
        sm = SIPManager(protocol=args.protocol)
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
                bind_ip=args.bind_ip,
                bind_port=args.src_port,
                timeout=args.timeout,
                cseq_start=args.cseq_start,
                ring_timeout=args.ring_timeout,
                talk_time=args.talk_time,
                codec=args.codec,
                rtp_port=args.rtp_port,
            )
        except KeyboardInterrupt:
            raise SystemExit(130)
        except OSError as e:
            logger.error(
                f"No se pudo bindear UDP en {args.bind_ip or '0.0.0.0'}:{args.src_port}: {e}"
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
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(((args.bind_ip or "0.0.0.0"), args.src_port or 0))
        except OSError as e:
            logger.error(
                f"No se pudo bindear UDP en {args.bind_ip or '0.0.0.0'}:{args.src_port}: {e}"
            )
            raise SystemExit(1)

        local_ip = args.bind_ip or sock.getsockname()[0]
        local_port = sock.getsockname()[1]
        contact_ip = args.advertised_ip or local_ip
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
                            if args.bind_ip:
                                contact_ip_resp = args.bind_ip
                            else:
                                tmp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                try:
                                    tmp.connect(addr)
                                    contact_ip_resp = tmp.getsockname()[0]
                                except OSError:
                                    contact_ip_resp = sock.getsockname()[0]
                                finally:
                                    tmp.close()
                            resp = (
                                "SIP/2.0 200 OK\r\n"
                                f"Via: {via}\r\n"
                                f"From: {fr}\r\n"
                                f"To: {to}\r\n"
                                f"Call-ID: {call_id}\r\n"
                                f"CSeq: {cseq_hdr}\r\n"
                                f"Contact: <sip:{user}@{contact_ip_resp}:{sock.getsockname()[1]}>\r\n"
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
                                "Contact": f"<sip:{user}@{contact_ip}:{sock.getsockname()[1]}>",
                                "Content-Type": "application/sdp",
                            }
                            sdp = build_sdp(contact_ip, args.uas_rtp_port, args.uas_codec)
                            sock.sendto(
                                build_response(200, "OK", headers, sdp), dialog["peer_addr"]
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
                                    "Contact": f"<sip:{user}@{contact_ip}:{sock.getsockname()[1]}>",
                                    "Content-Type": "application/sdp",
                                }
                                sdp = build_sdp(contact_ip, args.uas_rtp_port, args.uas_codec)
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
                            schedule(key, "del", 5)
                        elif etype == "del":
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
