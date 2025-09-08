import logging
import re
import socket
import time
import uuid
from typing import Tuple
from rtp import RtpSession

logger = logging.getLogger("socket_handler")


def normalize_number(s: str) -> str:
    """Return the number normalized removing spaces/hyphens."""
    s = s.replace(" ", "").replace("-", "")
    if re.fullmatch(r"\+?\d+", s):
        return s
    raise ValueError("numero invalido")


def make_uri(user: str, domain: str) -> str:
    """Build a SIP URI from user and domain."""
    return f"sip:{user}@{domain}"


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
    request_uri: str,
    from_uri: str,
    to_uri: str,
    local_ip: str,
    local_port: int,
    call_id: str,
    cseq: int,
    tag: str,
    branch: str,
    sdp: str,
    from_display: str | None = None,
    contact_user: str | None = None,
    pai: str | None = None,
    use_pai: bool = False,
    use_pai_asserted: bool = False,
) -> bytes:
    sent_by = f"{local_ip}:{local_port}"
    content_length = len(sdp.encode())
    from_hdr = f"<{from_uri}>;tag={tag}"
    if from_display:
        from_hdr = f'"{from_display}" {from_hdr}'
    msg = (
        f"INVITE {request_uri} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {sent_by};branch={branch};rport\r\n"
        "Max-Forwards: 70\r\n"
        f"From: {from_hdr}\r\n"
        f"To: <{to_uri}>\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: {cseq} INVITE\r\n"
        f"Contact: <sip:{contact_user}@{local_ip}:{local_port}>\r\n"
        "User-Agent: Dimitri-4000/0.1\r\n"
        "Allow: INVITE, ACK, CANCEL, BYE, OPTIONS\r\n"
    )
    if use_pai and pai:
        msg += f"P-Preferred-Identity: <{pai}>\r\n"
    if use_pai_asserted and pai:
        msg += f"P-Asserted-Identity: <{pai}>\r\n"
    msg += (
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
    from_uri: str,
    from_display: str | None,
    call_id: str,
    cseq: int,
    tag: str,
    contact_user: str,
) -> bytes:
    branch = "z9hG4bK" + uuid.uuid4().hex
    sent_by = f"{local_ip}:{local_port}"
    from_hdr = f"<{from_uri}>;tag={tag}"
    if from_display:
        from_hdr = f'"{from_display}" {from_hdr}'
    msg = (
        f"ACK {request_uri} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {sent_by};branch={branch};rport\r\n"
        "Max-Forwards: 70\r\n"
        f"From: {from_hdr}\r\n"
        f"To: {to_header}\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: {cseq} ACK\r\n"
        f"Contact: <sip:{contact_user}@{local_ip}:{local_port}>\r\n"
        "User-Agent: Dimitri-4000/0.1\r\n"
        "Allow: INVITE, ACK, CANCEL, BYE, OPTIONS\r\n"
        "Content-Length: 0\r\n\r\n"
    )
    return msg.encode()


def build_cancel(
    request_uri: str,
    to_uri: str,
    local_ip: str,
    local_port: int,
    from_uri: str,
    from_display: str | None,
    call_id: str,
    cseq: int,
    tag: str,
    branch: str,
    contact_user: str,
) -> bytes:
    sent_by = f"{local_ip}:{local_port}"
    from_hdr = f"<{from_uri}>;tag={tag}"
    if from_display:
        from_hdr = f'"{from_display}" {from_hdr}'
    msg = (
        f"CANCEL {request_uri} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {sent_by};branch={branch};rport\r\n"
        "Max-Forwards: 70\r\n"
        f"From: {from_hdr}\r\n"
        f"To: <{to_uri}>\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: {cseq} CANCEL\r\n"
        f"Contact: <sip:{contact_user}@{local_ip}:{local_port}>\r\n"
        "User-Agent: Dimitri-4000/0.1\r\n"
        "Content-Length: 0\r\n\r\n"
    )
    return msg.encode()


def build_bye_request(
    request_uri: str,
    to_header: str,
    local_ip: str,
    local_port: int,
    from_uri: str,
    from_display: str | None,
    call_id: str,
    cseq: int,
    tag: str,
    contact_user: str,
) -> bytes:
    """Build a BYE request for the caller side (UAC)."""
    branch = "z9hG4bK" + uuid.uuid4().hex
    sent_by = f"{local_ip}:{local_port}"
    from_hdr = f"<{from_uri}>;tag={tag}"
    if from_display:
        from_hdr = f'"{from_display}" {from_hdr}'
    msg = (
        f"BYE {request_uri} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {sent_by};branch={branch};rport\r\n"
        "Max-Forwards: 70\r\n"
        f"From: {from_hdr}\r\n"
        f"To: {to_header}\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: {cseq} BYE\r\n"
        f"Contact: <sip:{contact_user}@{local_ip}:{local_port}>\r\n"
        "User-Agent: Dimitri-4000/0.1\r\n"
        "Content-Length: 0\r\n\r\n"
    )
    return msg.encode()


def _contact_uri_host_port(contact: str) -> Tuple[str, str, int | None]:
    """Return (uri, host, port) extracted from a Contact header.

    If the URI lacks an explicit port, ``port`` is ``None`` so that the caller
    can decide the appropriate default (e.g. the source port of the response).
    """
    uri = contact
    if "<" in contact and ">" in contact:
        uri = contact.split("<", 1)[1].split(">", 1)[0]
    hostport = uri.split("@")[-1]
    if ":" in hostport:
        host, port_s = hostport.split(":", 1)
        try:
            port = int(port_s)
        except ValueError:
            port = None
    else:
        host, port = hostport, None
    return uri, host, port


def build_response(
    status: int,
    reason: str,
    headers: dict,
    body: bytes | str = b"",
) -> bytes:
    """Build a generic SIP response."""
    lines = [f"SIP/2.0 {status} {reason}\r\n"]
    for k, v in headers.items():
        lines.append(f"{k}: {v}\r\n")
    if body:
        if isinstance(body, str):
            body = body.encode()
        lines.append(f"Content-Length: {len(body)}\r\n\r\n")
        return ("".join(lines).encode() + body)
    else:
        lines.append("Content-Length: 0\r\n\r\n")
        return "".join(lines).encode()


def build_sdp(local_ip: str, rtp_port: int, pt: int) -> str:
    """Return a minimal SDP offer/answer for a single codec."""
    codec = "PCMU" if pt == 0 else "PCMA"
    return (
        "v=0\r\n"
        f"o=dimitri 0 0 IN IP4 {local_ip}\r\n"
        "s=Dimitri-4000\r\n"
        f"c=IN IP4 {local_ip}\r\n"
        "t=0 0\r\n"
        f"m=audio {rtp_port} RTP/AVP {pt}\r\n"
        f"a=rtpmap:{pt} {codec}/8000\r\n"
        "a=sendrecv\r\n"
    )


def parse_sdp(text: str) -> tuple[str | None, int | None, int | None]:
    """Extract connection IP, port and PT from SDP."""
    ip = None
    port = None
    pt = None
    for line in text.splitlines():
        if line.startswith("c=") and ip is None:
            parts = line.split()
            if len(parts) >= 3:
                ip = parts[2]
        elif line.startswith("m=audio") and port is None:
            parts = line.split()
            if len(parts) >= 4:
                try:
                    port = int(parts[1])
                    pt = int(parts[3])
                except ValueError:
                    pass
    return ip, port, pt


def build_bye(dialog: dict) -> bytes:
    """Build a BYE request from stored dialog information (UAS side)."""
    branch = "z9hG4bK" + uuid.uuid4().hex
    sent_by = f"{dialog['local_ip']}:{dialog['local_port']}"
    req_uri = dialog.get("peer_uri")
    from_hdr = f"{dialog['to_uri']};tag={dialog['local_tag']}"
    to_hdr = dialog['from_uri']
    cseq = dialog['our_next_cseq']
    dialog['our_next_cseq'] += 1
    msg = (
        f"BYE {req_uri} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {sent_by};branch={branch};rport\r\n"
        "Max-Forwards: 70\r\n"
        f"From: {from_hdr}\r\n"
        f"To: {to_hdr}\r\n"
        f"Call-ID: {dialog['call_id']}\r\n"
        f"CSeq: {cseq} BYE\r\n"
        f"Contact: <sip:dimitri@{dialog['local_ip']}>\r\n"
        "User-Agent: Dimitri-4000/0.1\r\n"
        "Content-Length: 0\r\n\r\n"
    )
    return msg.encode()


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
        from_number: str | None = None,
        from_domain: str | None = None,
        from_display: str | None = None,
        to_number: str | None = None,
        to_domain: str | None = None,
        from_uri: str | None = None,
        to_uri: str | None = None,
        pai: str | None = None,
        use_pai: bool = False,
        use_pai_asserted: bool = False,
        bind_ip: str | None = None,
        bind_port: int = 0,
        timeout: float = 2.0,
        cseq_start: int = 1,
        ring_timeout: float = 15.0,
        talk_time: float = 5.0,
        codec: str = "pcmu",
        rtp_port: int = 40000,
        rtcp: bool = False,
        tone_hz: int | None = None,
        send_silence: bool = False,
        symmetric: bool = False,
        save_wav: str | None = None,
        stats_interval: float = 2.0,
    ) -> tuple[str, str, int, float]:
        if self.protocol != "udp":
            raise NotImplementedError("Solo UDP por ahora.")

        s, local_ip, local_port = self._open_connected_udp(
            dst_host, dst_port, bind_ip, bind_port
        )
        s.settimeout(0.5)

        if from_uri:
            if not from_uri.startswith("sip:"):
                raise ValueError("from_uri debe empezar por sip:")
            from_user = from_uri.split("sip:", 1)[1].split("@", 1)[0]
        else:
            from_user = normalize_number(from_number) if from_number else "dimitri"
            from_uri = make_uri(from_user, from_domain or local_ip)

        if to_uri:
            if not to_uri.startswith("sip:"):
                raise ValueError("to_uri debe empezar por sip:")
            to_user = to_uri.split("sip:", 1)[1].split("@", 1)[0]
            to_domain_part = to_uri.split("@", 1)[1]
            req_host = dst_host or to_domain_part.split(";", 1)[0]
            request_uri = make_uri(to_user, req_host)
        else:
            if not to_number:
                raise ValueError("Falta numero destino")
            to_user = normalize_number(to_number)
            to_uri = make_uri(to_user, to_domain or dst_host)
            request_uri = make_uri(to_user, dst_host)

        contact_user = from_user

        call_id = str(uuid.uuid4())
        branch = "z9hG4bK" + uuid.uuid4().hex
        tag = uuid.uuid4().hex[:8]
        pt = 0 if codec.lower() == "pcmu" else 8
        sdp = build_sdp(local_ip, rtp_port, pt)
        invite = build_invite(
            request_uri,
            from_uri,
            to_uri,
            local_ip,
            local_port,
            call_id,
            cseq_start,
            tag,
            branch,
            sdp,
            from_display=from_display,
            contact_user=contact_user,
            pai=pai,
            use_pai=use_pai,
            use_pai_asserted=use_pai_asserted,
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
        cancel_deadline = None
        contact_uri = request_uri
        to_header = f"<{to_uri}>"
        setup_ms = None
        result = "timeout"

        try:
            while True:
                now = time.monotonic()
                if not canceled and now >= ring_deadline:
                    cancel = build_cancel(
                        request_uri,
                        to_uri,
                        local_ip,
                        local_port,
                        from_uri,
                        from_display,
                        call_id,
                        cseq_start,
                        tag,
                        branch,
                        contact_user,
                    )
                    s.send(cancel)
                    logger.info("Ring timeout, enviado CANCEL")
                    canceled = True
                    cancel_deadline = now + 5
                    continue

                if canceled and cancel_deadline and now >= cancel_deadline:
                    result = "canceled-timeout"
                    break

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

                if canceled:
                    if code == 200:
                        logger.info("200 OK tras CANCEL")
                        continue
                    if code == 487:
                        to_header = headers.get("to", to_header)
                        ack = build_ack(
                            request_uri,
                            to_header,
                            local_ip,
                            local_port,
                            from_uri,
                            from_display,
                            call_id,
                            cseq_start,
                            tag,
                            contact_user,
                        )
                        s.send(ack)
                        setup_ms = int((time.monotonic() - t_start) * 1000)
                        result = "canceled"
                        break
                    continue

                if code in (100, 180, 183):
                    logger.info(f"Recibido {code} {reason}")
                    continue

                if code == 200:
                    setup_ms = int((time.monotonic() - t_start) * 1000)
                    logger.info(f"200 OK en {setup_ms} ms")
                    to_header = headers.get("to", to_header)
                    contact = headers.get("contact")
                    body = b""
                    if b"\r\n\r\n" in data:
                        body = data.split(b"\r\n\r\n", 1)[1]
                    rip, rport, rpt = parse_sdp(body.decode(errors="ignore"))
                    remote_ip = rip or dst_host
                    remote_port = rport or rtp_port
                    payload_pt = rpt if rpt is not None else pt
                    rtp = RtpSession(
                        local_ip,
                        rtp_port,
                        payload_pt,
                        symmetric=symmetric,
                        save_wav=save_wav,
                    )
                    rtp.rtcp = rtcp
                    rtp.tone_hz = tone_hz
                    rtp.send_silence = send_silence and not tone_hz
                    rtp.stats_interval = stats_interval
                    rtp.start(remote_ip, remote_port)
                    to_header = headers.get("to", to_header)
                    contact = headers.get("contact")
                    if contact:
                        contact_uri, host, port = _contact_uri_host_port(contact)
                        if port is None:
                            try:
                                port = s.getpeername()[1]
                            except OSError:
                                port = 5060
                            # insert the fallback port into the URI for the
                            # request line so that the ACK targets the correct
                            # socket.
                            if "@" in contact_uri:
                                user_part, host_part = contact_uri.split("@", 1)
                                if ";" in host_part:
                                    host_only, params = host_part.split(";", 1)
                                    contact_uri = (
                                        f"{user_part}@{host_only}:{port};{params}"
                                    )
                                else:
                                    contact_uri = f"{user_part}@{host_part}:{port}"
                            elif contact_uri.startswith("sip:"):
                                host_only = contact_uri[4:]
                                contact_uri = f"sip:{host_only}:{port}"
                        try:
                            s.connect((host, port))
                        except OSError:
                            pass
                    ack = build_ack(
                        contact_uri,
                        to_header,
                        local_ip,
                        local_port,
                        from_uri,
                        from_display,
                        call_id,
                        cseq_start,
                        tag,
                        contact_user,
                    )
                    s.send(ack)
                    if talk_time > 0:
                        time.sleep(talk_time)
                        bye = build_bye_request(
                            contact_uri,
                            to_header,
                            local_ip,
                            local_port,
                            from_uri,
                            from_display,
                            call_id,
                            cseq_start + 1,
                            tag,
                            contact_user,
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
                        request_uri,
                        to_header,
                        local_ip,
                        local_port,
                        from_uri,
                        from_display,
                        call_id,
                        cseq_start,
                        tag,
                        contact_user,
                    )
                    s.send(ack)
                    setup_ms = int((time.monotonic() - t_start) * 1000)
                    result = "canceled"
                    break

                if code is not None and code >= 400:
                    to_header = headers.get("to", to_header)
                    ack = build_ack(
                        request_uri,
                        to_header,
                        local_ip,
                        local_port,
                        from_uri,
                        from_display,
                        call_id,
                        cseq_start,
                        tag,
                        contact_user,
                    )
                    s.send(ack)
                    setup_ms = int((time.monotonic() - t_start) * 1000)
                    if code == 486:
                        result = "busy(486)"
                    else:
                        result = f"rejected({code})"
                    break

        except KeyboardInterrupt:
            logger.info("Llamada abortada por usuario")
            result = "aborted"
            raise
        finally:
            s.close()
            if 'rtp' in locals():
                rtp.stop()

        talk_s = talk_time if result == "answered" else 0
        return call_id, result, setup_ms or 0, talk_s
