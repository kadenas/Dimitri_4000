import logging
import socket
import time
import uuid
from typing import Tuple

from sdp import build_sdp

logger = logging.getLogger("socket_handler")


def status_from_response(data: bytes):
    """Devuelve (codigo, razon) a partir de la primera línea SIP."""
    try:
        line0 = data.decode(errors="ignore").splitlines()[0]
        parts = line0.split(" ", 2)
        code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
        reason = parts[2] if len(parts) > 2 else ""
        return code, reason
    except Exception:
        return None, ""


def build_options(
    dst_host: str, local_ip: str, local_port: int, user: str, cseq: int
) -> tuple[str, bytes]:
    """Construye un mensaje OPTIONS y devuelve (call-id, bytes)."""
    call_id = str(uuid.uuid4())
    branch = "z9hG4bK" + call_id.replace("-", "")
    sent_by = f"{local_ip}:{local_port}"  # SIEMPRE con puerto real
    msg = (
        f"OPTIONS sip:{dst_host} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {sent_by};branch={branch};rport\r\n"
        f"Max-Forwards: 70\r\n"
        f"From: <sip:{user}@{local_ip}>;tag={user}\r\n"
        f"To: <sip:{dst_host}>\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: {cseq} OPTIONS\r\n"
        f"Contact: <sip:{user}@{local_ip}>\r\n"
        f"User-Agent: Dimitri-4000/0.1\r\n"
        f"Allow: INVITE, ACK, CANCEL, OPTIONS, BYE\r\n"
        f"Accept: application/sdp\r\n"
        f"Content-Length: 0\r\n\r\n"
    )
    return call_id, msg.encode()


def build_invite(
    to_uri: str,
    local_ip: str,
    local_port: int,
    from_user: str,
    call_id: str,
    cseq: int,
    tag: str,
    branch: str,
    sdp: str,
) -> bytes:
    sent_by = f"{local_ip}:{local_port}"
    content_length = len(sdp.encode())
    msg = (
        f"INVITE {to_uri} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {sent_by};branch={branch};rport\r\n"
        "Max-Forwards: 70\r\n"
        f"From: \"{from_user}\" <sip:{from_user}@{local_ip}>;tag={tag}\r\n"
        f"To: <{to_uri}>\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: {cseq} INVITE\r\n"
        f"Contact: <sip:{from_user}@{local_ip}>\r\n"
        "User-Agent: Dimitri-4000/0.1\r\n"
        "Allow: INVITE, ACK, CANCEL, BYE, OPTIONS\r\n"
        "Content-Type: application/sdp\r\n"
        f"Content-Length: {content_length}\r\n\r\n"
        f"{sdp}"
    )
    return msg.encode()


def build_ack(
    request_uri: str,
    to_header: str,
    local_ip: str,
    local_port: int,
    from_user: str,
    call_id: str,
    cseq: int,
    tag: str,
) -> bytes:
    branch = "z9hG4bK" + uuid.uuid4().hex
    sent_by = f"{local_ip}:{local_port}"
    msg = (
        f"ACK {request_uri} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {sent_by};branch={branch};rport\r\n"
        "Max-Forwards: 70\r\n"
        f"From: \"{from_user}\" <sip:{from_user}@{local_ip}>;tag={tag}\r\n"
        f"To: {to_header}\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: {cseq} ACK\r\n"
        f"Contact: <sip:{from_user}@{local_ip}>\r\n"
        "User-Agent: Dimitri-4000/0.1\r\n"
        "Allow: INVITE, ACK, CANCEL, BYE, OPTIONS\r\n"
        "Content-Length: 0\r\n\r\n"
    )
    return msg.encode()


def build_cancel(
    to_uri: str,
    local_ip: str,
    local_port: int,
    from_user: str,
    call_id: str,
    cseq: int,
    tag: str,
    branch: str,
) -> bytes:
    sent_by = f"{local_ip}:{local_port}"
    msg = (
        f"CANCEL {to_uri} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {sent_by};branch={branch};rport\r\n"
        "Max-Forwards: 70\r\n"
        f"From: \"{from_user}\" <sip:{from_user}@{local_ip}>;tag={tag}\r\n"
        f"To: <{to_uri}>\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: {cseq} CANCEL\r\n"
        f"Contact: <sip:{from_user}@{local_ip}>\r\n"
        "User-Agent: Dimitri-4000/0.1\r\n"
        "Content-Length: 0\r\n\r\n"
    )
    return msg.encode()


def build_bye(
    request_uri: str,
    to_header: str,
    local_ip: str,
    local_port: int,
    from_user: str,
    call_id: str,
    cseq: int,
    tag: str,
) -> bytes:
    branch = "z9hG4bK" + uuid.uuid4().hex
    sent_by = f"{local_ip}:{local_port}"
    msg = (
        f"BYE {request_uri} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {sent_by};branch={branch};rport\r\n"
        "Max-Forwards: 70\r\n"
        f"From: \"{from_user}\" <sip:{from_user}@{local_ip}>;tag={tag}\r\n"
        f"To: {to_header}\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: {cseq} BYE\r\n"
        f"Contact: <sip:{from_user}@{local_ip}>\r\n"
        "User-Agent: Dimitri-4000/0.1\r\n"
        "Content-Length: 0\r\n\r\n"
    )
    return msg.encode()


def _contact_uri_host_port(contact: str) -> Tuple[str, str, int]:
    uri = contact
    if "<" in contact and ">" in contact:
        uri = contact.split("<", 1)[1].split(">", 1)[0]
    hostport = uri.split("@")[-1]
    if ":" in hostport:
        host, port_s = hostport.split(":", 1)
        try:
            port = int(port_s)
        except ValueError:
            port = 5060
    else:
        host, port = hostport, 5060
    return uri, host, port


def parse_headers(data: bytes):
    """Parsea cabeceras SIP mínimas y devuelve (start_line, dict)."""
    try:
        text = data.decode(errors="ignore")
    except Exception:
        return "", {}
    lines = text.split("\r\n")
    start = lines[0] if lines else ""
    headers = {}
    for line in lines[1:]:
        if not line:
            break
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return start, headers


class SIPManager:
    def __init__(self, protocol: str = "udp"):
        self.protocol = protocol

    def _open_connected_udp(
        self,
        dst_host: str,
        dst_port: int,
        bind_ip: str | None,
        bind_port: int,
    ):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(((bind_ip or "0.0.0.0"), bind_port or 0))
            s.connect((dst_host, dst_port))
            local_ip, local_port = s.getsockname()
            return s, local_ip, local_port
        except OSError:
            s.close()
            raise

    def send_request(
        self,
        dst_host: str,
        dst_port: int = 5060,
        timeout: float = 2.0,
        bind_ip: str | None = None,
        bind_port: int = 0,
        cseq: int = 1,
        user: str = "dimitri",
    ):
        if self.protocol != "udp":
            raise NotImplementedError("Solo UDP por ahora.")

        try:
            s, local_ip, local_port = self._open_connected_udp(
                dst_host, dst_port, bind_ip, bind_port
            )
        except OSError as e:
            logger.error(
                f"No se pudo bindear UDP en {bind_ip or '0.0.0.0'}:{bind_port}: {e}"
            )
            raise

        s.settimeout(timeout)

        _call_id, payload = build_options(dst_host, local_ip, local_port, user, cseq)

        t0 = time.time()
        logger.info(
            f"Enviando UDP a {dst_host}:{dst_port} sent-by={local_ip}:{local_port}"
        )
        s.send(payload)
        try:
            data = s.recv(2048)
            rtt_ms = int((time.time() - t0) * 1000)
            logger.info(f"UDP recibido de {dst_host}:{dst_port}")
            code, reason = status_from_response(data)
            return code, reason, rtt_ms
        except socket.timeout:
            return None, None, None
        finally:
            logger.info("Socket UDP cerrado")
            s.close()

    def place_call(
        self,
        dst_host: str,
        dst_port: int,
        to_uri: str,
        from_user: str = "dimitri",
        bind_ip: str | None = None,
        bind_port: int = 0,
        timeout: float = 2.0,
        cseq_start: int = 1,
        ring_timeout: float = 15.0,
        talk_time: float = 5.0,
        codec: str = "pcmu",
        rtp_port: int = 40000,
    ) -> tuple[str, str, int, float]:
        if self.protocol != "udp":
            raise NotImplementedError("Solo UDP por ahora.")

        s, local_ip, local_port = self._open_connected_udp(
            dst_host, dst_port, bind_ip, bind_port
        )
        s.settimeout(0.5)

        call_id = str(uuid.uuid4())
        branch = "z9hG4bK" + uuid.uuid4().hex
        tag = uuid.uuid4().hex[:8]
        sdp = build_sdp(local_ip, rtp_port, codec)
        invite = build_invite(
            to_uri,
            local_ip,
            local_port,
            from_user,
            call_id,
            cseq_start,
            tag,
            branch,
            sdp,
        )

        logger.info(
            f"Enviando INVITE (CSeq={cseq_start}) a {dst_host}:{dst_port} sent-by={local_ip}:{local_port}"
        )
        s.send(invite)
        t_start = time.monotonic()
        t1 = 0.5
        next_resend = t_start + t1
        ring_deadline = t_start + ring_timeout
        canceled = False
        contact_uri = to_uri
        to_header = f"<{to_uri}>"
        setup_ms = None
        result = "timeout"

        while True:
            now = time.monotonic()
            if not canceled and now >= ring_deadline:
                cancel = build_cancel(
                    to_uri,
                    local_ip,
                    local_port,
                    from_user,
                    call_id,
                    cseq_start,
                    tag,
                    branch,
                )
                s.send(cancel)
                logger.info("Ring timeout, enviado CANCEL")
                canceled = True
                continue

            try:
                data = s.recv(4096)
            except socket.timeout:
                now = time.monotonic()
                if not canceled and now >= next_resend:
                    s.send(invite)
                    t1 = min(t1 * 2, 4.0)
                    next_resend = now + t1
                continue

            code, reason = status_from_response(data)
            start, headers = parse_headers(data)
            if code in (100, 180, 183):
                logger.info(f"Recibido {code} {reason}")
                continue

            if code == 200:
                if canceled:
                    logger.info("200 OK tras CANCEL")
                    continue
                setup_ms = int((time.monotonic() - t_start) * 1000)
                logger.info(f"200 OK en {setup_ms} ms")
                to_header = headers.get("to", to_header)
                contact = headers.get("contact")
                if contact:
                    contact_uri, host, port = _contact_uri_host_port(contact)
                    try:
                        s.connect((host, port))
                    except OSError:
                        pass
                ack = build_ack(
                    contact_uri,
                    to_header,
                    local_ip,
                    local_port,
                    from_user,
                    call_id,
                    cseq_start,
                    tag,
                )
                s.send(ack)
                if talk_time > 0:
                    time.sleep(talk_time)
                    bye = build_bye(
                        contact_uri,
                        to_header,
                        local_ip,
                        local_port,
                        from_user,
                        call_id,
                        cseq_start + 1,
                        tag,
                    )
                    s.send(bye)
                    while True:
                        try:
                            data2 = s.recv(4096)
                        except socket.timeout:
                            break
                        c2, _ = status_from_response(data2)
                        if c2 == 200:
                            logger.info("200 OK al BYE")
                            break
                result = "answered"
                break

            if code == 487:
                to_header = headers.get("to", to_header)
                ack = build_ack(
                    to_uri,
                    to_header,
                    local_ip,
                    local_port,
                    from_user,
                    call_id,
                    cseq_start,
                    tag,
                )
                s.send(ack)
                setup_ms = int((time.monotonic() - t_start) * 1000)
                result = "canceled"
                break

            if code is not None and code >= 400:
                to_header = headers.get("to", to_header)
                ack = build_ack(
                    to_uri,
                    to_header,
                    local_ip,
                    local_port,
                    from_user,
                    call_id,
                    cseq_start,
                    tag,
                )
                s.send(ack)
                setup_ms = int((time.monotonic() - t_start) * 1000)
                if code == 486:
                    result = "busy(486)"
                else:
                    result = f"rejected({code})"
                break

        s.close()
        talk_s = talk_time if result == "answered" else 0
        return call_id, result, setup_ms or 0, talk_s
