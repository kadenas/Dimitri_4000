import logging
import re
import socket
import time
import uuid
import hashlib
import secrets
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


def parse_auth(challenge: str) -> dict:
    """Parse a WWW-/Proxy-Authenticate header with Digest scheme."""
    result: dict[str, str] = {}
    if not challenge or not challenge.lower().startswith("digest"):
        return result
    params = challenge[len("Digest"):].split(",")
    for p in params:
        if "=" in p:
            k, v = p.strip().split("=", 1)
            v = v.strip().strip('"')
            result[k.lower()] = v
    return result


def build_digest_auth(
    method: str,
    uri: str,
    user: str,
    password: str,
    realm: str,
    nonce: str,
    qop: str,
    cnonce: str,
    nc: int,
    alg: str = "MD5",
    opaque: str | None = None,
) -> str:
    """Return the value for Authorization/Proxy-Authorization (Digest)."""
    ha1 = hashlib.md5(f"{user}:{realm}:{password}".encode()).hexdigest()
    ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
    resp = hashlib.md5(
        f"{ha1}:{nonce}:{nc:08x}:{cnonce}:{qop}:{ha2}".encode()
    ).hexdigest()
    parts = [
        f'username="{user}"',
        f'realm="{realm}"',
        f'nonce="{nonce}"',
        f'uri="{uri}"',
        f'response="{resp}"',
        "algorithm=MD5",
        f'cnonce="{cnonce}"',
        f'nc={nc:08x}',
        f'qop={qop}',
    ]
    if opaque:
        parts.append(f'opaque="{opaque}"')
    return "Digest " + ", ".join(parts)


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
    auth_header: tuple[str, str] | None = None,
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
    if auth_header:
        msg += f"{auth_header[0]}: {auth_header[1]}\r\n"
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
    auth_header: tuple[str, str] | None = None,
    route_set: list[str] | None = None,
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
    )
    if route_set:
        for r in route_set:
            msg += f"Route: {r}\r\n"
    msg += (
        f"Contact: <sip:{contact_user}@{local_ip}:{local_port}>\r\n"
        "User-Agent: Dimitri-4000/0.1\r\n"
    )
    if auth_header:
        msg += f"{auth_header[0]}: {auth_header[1]}\r\n"
    msg += "Content-Length: 0\r\n\r\n"
    return msg.encode()


def _contact_uri_host_port(contact: str) -> Tuple[str, str, int | None]:
    """Return (uri, host, port) extracted from a Contact header.

    If the URI lacks an explicit port, ``port`` is ``None`` so that the caller
    can decide the appropriate default (e.g. the source port of the response).
    """
    uri = contact
    if "<" in contact and ">" in contact:
        uri = contact.split("<", 1)[1].split(">", 1)[0]
    uri_no_scheme = uri[4:] if uri.lower().startswith("sip:") else uri
    hostport = uri_no_scheme.split("@")[-1]
    if ";" in hostport:
        hostport = hostport.split(";", 1)[0]
    if ":" in hostport:
        host, port_s = hostport.split(":", 1)
        try:
            port = int(port_s)
        except ValueError:
            port = None
    else:
        host, port = hostport, None
    return uri, host, port


def _route_set_from_record_route(rr_header: str) -> list[str]:
    """Return a route set (reversed) from a Record-Route header value."""
    if not rr_header:
        return []
    parts = []
    current = []
    depth = 0
    for ch in rr_header:
        if ch == ',' and depth == 0:
            part = ''.join(current).strip()
            if part:
                parts.append(part)
            current = []
            continue
        if ch == '<':
            depth += 1
        elif ch == '>':
            if depth > 0:
                depth -= 1
        current.append(ch)
    part = ''.join(current).strip()
    if part:
        parts.append(part)
    return list(reversed(parts))


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
        auth_user: str | None = None,
        auth_pass: str | None = None,
        auth_realm: str | None = None,
        auth_username: str | None = None,
        bind_ip: str | None = None,
        bind_port: int = 0,
        timeout: float = 2.0,
        cseq_start: int = 1,
        ring_timeout: float = 15.0,
        talk_time: float = 5.0,
        wait_bye: bool = False,
        max_call_time: float = 0.0,
        codec: str = "pcmu",
        rtp_port: int = 40000,
        rtp_port_forced: bool = False,
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
        invite_cseq = cseq_start
        auth_username = auth_username or auth_user or from_user
        auth_state = {"nc": 0, "realm": auth_realm, "nonce": None, "opaque": None, "qop": "auth", "proxy": False}

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
            invite_cseq,
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
            f"Enviando INVITE (CSeq={invite_cseq}) a {dst_host}:{dst_port} sent-by={local_ip}:{local_port}"
        )
        s.send(invite)
        t_start = time.monotonic()
        t1 = 0.5
        next_resend = t_start + t1
        ring_deadline = t_start + ring_timeout
        canceled = False
        cancel_deadline = None
        remote_target = request_uri
        route_set: list[str] = []
        to_header = f"<{to_uri}>"
        
        def send_bye(cseq: int) -> int:
            nonlocal to_header, remote_target
            auth_hdr = None
            if auth_user and auth_pass and auth_state.get("nonce"):
                cnonce = secrets.token_hex(8)
                auth_state["nc"] = auth_state.get("nc", 0) + 1
                auth_val = build_digest_auth(
                    "BYE",
                    remote_target,
                    auth_username,
                    auth_pass,
                    auth_state["realm"],
                    auth_state["nonce"],
                    auth_state.get("qop", "auth"),
                    cnonce,
                    auth_state["nc"],
                    opaque=auth_state.get("opaque"),
                )
                hdr_name = "Proxy-Authorization" if auth_state.get("proxy") else "Authorization"
                auth_hdr = (hdr_name, auth_val)
            send_uri = remote_target
            if route_set:
                last = route_set[-1]
                if remote_target not in last:
                    send_uri = route_set[0]
            if send_uri != remote_target:
                try:
                    _, h, p = _contact_uri_host_port(send_uri)
                    if p is None:
                        p = s.getpeername()[1]
                    s.connect((h, p))
                except Exception:
                    pass
            bye = build_bye_request(
                remote_target,
                to_header,
                local_ip,
                local_port,
                from_uri,
                from_display,
                call_id,
                cseq,
                tag,
                contact_user,
                auth_header=auth_hdr,
                route_set=route_set,
            )
            s.send(bye)
            while True:
                try:
                    data2 = s.recv(4096)
                except socket.timeout:
                    return cseq
                start2, headers2 = parse_headers(data2)
                c2, _ = status_from_response(data2)
                if c2 in (401, 407) and auth_user and auth_pass and not auth_state.get("bye_auth_done"):
                    chall = headers2.get("www-authenticate" if c2 == 401 else "proxy-authenticate")
                    if chall:
                        params = parse_auth(chall)
                        realm = auth_realm or params.get("realm", "")
                        nonce = params.get("nonce", "")
                        opaque = params.get("opaque")
                        qop = params.get("qop", "auth")
                        auth_state.update({"realm": realm, "nonce": nonce, "opaque": opaque, "qop": qop, "proxy": c2 == 407})
                        to_hdr = headers2.get("to", to_header)
                        to_header = to_hdr
                        ack = build_ack(
                            remote_target,
                            to_hdr,
                            local_ip,
                            local_port,
                            from_uri,
                            from_display,
                            call_id,
                            cseq,
                            tag,
                            contact_user,
                        )
                        s.send(ack)
                        cseq += 1
                        cnonce = secrets.token_hex(8)
                        auth_state["nc"] = auth_state.get("nc", 0) + 1
                        auth_val = build_digest_auth(
                            "BYE",
                            remote_target,
                            auth_username,
                            auth_pass,
                            realm,
                            nonce,
                            qop,
                            cnonce,
                            auth_state["nc"],
                            opaque=opaque,
                        )
                        hdr_name = "Proxy-Authorization" if c2 == 407 else "Authorization"
                        bye = build_bye_request(
                            remote_target,
                            to_hdr,
                            local_ip,
                            local_port,
                            from_uri,
                            from_display,
                            call_id,
                            cseq,
                            tag,
                            contact_user,
                            auth_header=(hdr_name, auth_val),
                            route_set=route_set,
                        )
                        s.send(bye)
                        auth_state["bye_auth_done"] = True
                        continue
                if c2 == 200:
                    logger.info("200 OK al BYE")
                    break
            return cseq

        setup_ms = None
        result = "timeout"

        call_established = False
        talk_start = None
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
                        invite_cseq,
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
                            invite_cseq,
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

                if code in (401, 407) and auth_user and auth_pass and not auth_state.get("invite_auth_done"):
                    header_name = "www-authenticate" if code == 401 else "proxy-authenticate"
                    challenge = headers.get(header_name)
                    if challenge:
                        params = parse_auth(challenge)
                        realm = auth_realm or params.get("realm", "")
                        nonce = params.get("nonce", "")
                        opaque = params.get("opaque")
                        qop = params.get("qop", "auth")
                        auth_state.update({"realm": realm, "nonce": nonce, "opaque": opaque, "qop": qop, "proxy": code == 407})
                        to_header = headers.get("to", to_header)
                        ack = build_ack(
                            request_uri,
                            to_header,
                            local_ip,
                            local_port,
                            from_uri,
                            from_display,
                            call_id,
                            invite_cseq,
                            tag,
                            contact_user,
                        )
                        s.send(ack)
                        invite_cseq += 1
                        cnonce = secrets.token_hex(8)
                        auth_state["nc"] = auth_state.get("nc", 0) + 1
                        auth_val = build_digest_auth(
                            "INVITE",
                            request_uri,
                            auth_username,
                            auth_pass,
                            realm,
                            nonce,
                            qop,
                            cnonce,
                            auth_state["nc"],
                            opaque=opaque,
                        )
                        hdr_name = "Proxy-Authorization" if code == 407 else "Authorization"
                        branch = "z9hG4bK" + uuid.uuid4().hex
                        invite = build_invite(
                            request_uri,
                            from_uri,
                            to_uri,
                            local_ip,
                            local_port,
                            call_id,
                            invite_cseq,
                            tag,
                            branch,
                            sdp,
                            from_display=from_display,
                            contact_user=contact_user,
                            pai=pai,
                            use_pai=use_pai,
                            use_pai_asserted=use_pai_asserted,
                            auth_header=(hdr_name, auth_val),
                        )
                        logger.info("Reenviando INVITE con autenticacion Digest")
                        s.send(invite)
                        t_start = time.monotonic()
                        t1 = 0.5
                        next_resend = t_start + t1
                        ring_deadline = t_start + ring_timeout
                        auth_state["invite_auth_done"] = True
                        continue

                if code == 200:
                    setup_ms = int((time.monotonic() - t_start) * 1000)
                    logger.info(f"200 OK en {setup_ms} ms")
                    to_header = headers.get("to", to_header)
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
                        forced=rtp_port_forced,
                    )
                    rtp.rtcp = rtcp
                    rtp.tone_hz = tone_hz
                    rtp.send_silence = send_silence and not tone_hz
                    rtp.stats_interval = stats_interval
                    rtp.start(remote_ip, remote_port)
                    to_header = headers.get("to", to_header)
                    contact = headers.get("contact")
                    if contact:
                        remote_target, host, port = _contact_uri_host_port(contact)
                        if port is None:
                            try:
                                port = s.getpeername()[1]
                            except OSError:
                                port = 5060
                            if "@" in remote_target:
                                user_part, host_part = remote_target.split("@", 1)
                                if ";" in host_part:
                                    host_only, params = host_part.split(";", 1)
                                    remote_target = f"{user_part}@{host_only}:{port};{params}"
                                else:
                                    remote_target = f"{user_part}@{host_part}:{port}"
                            elif remote_target.startswith("sip:"):
                                host_only = remote_target[4:]
                                remote_target = f"sip:{host_only}:{port}"
                        try:
                            s.connect((host, port))
                        except OSError:
                            pass
                    rr = headers.get("record-route")
                    if rr:
                        route_set = _route_set_from_record_route(rr)
                    ack = build_ack(
                        remote_target,
                        to_header,
                        local_ip,
                        local_port,
                        from_uri,
                        from_display,
                        call_id,
                        invite_cseq,
                        tag,
                        contact_user,
                    )
                    s.send(ack)
                    call_established = True
                    talk_start = time.monotonic()
                    if wait_bye:
                        s.settimeout(0.5)
                        try:
                            while True:
                                if (
                                    max_call_time > 0
                                    and time.monotonic() - talk_start >= max_call_time
                                ):
                                    invite_cseq = send_bye(invite_cseq + 1)
                                    result = "max-time-bye"
                                    break
                                try:
                                    data2 = s.recv(4096)
                                except socket.timeout:
                                    continue
                                start2, headers2 = parse_headers(data2)
                                if start2.startswith("BYE") and headers2.get(
                                    "call-id"
                                ) == call_id:
                                    resp = build_response(
                                        200,
                                        "OK",
                                        {
                                            "Via": headers2.get("via", ""),
                                            "From": headers2.get("from", ""),
                                            "To": headers2.get("to", ""),
                                            "Call-ID": headers2.get("call-id", ""),
                                            "CSeq": headers2.get("cseq", ""),
                                        },
                                    )
                                    s.send(resp)
                                    result = "remote-bye"
                                    break
                                c2, _ = status_from_response(data2)
                                if c2 == 200:
                                    s.send(ack)
                                    continue
                                if start2.startswith("INVITE") or start2.startswith(
                                    "UPDATE"
                                ):
                                    continue
                        except KeyboardInterrupt:
                            invite_cseq = send_bye(invite_cseq + 1)
                            result = "aborted"
                        break
                    if talk_time > 0:
                        time.sleep(talk_time)
                        invite_cseq = send_bye(invite_cseq + 1)
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
                        invite_cseq,
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
                        invite_cseq,
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
            if call_established and 'remote_target' in locals():
                try:
                    invite_cseq = send_bye(invite_cseq + 1)
                except OSError:
                    pass
            result = "aborted"
        finally:
            s.close()
            if 'rtp' in locals():
                rtp.stop()

        if talk_start:
            talk_s = time.monotonic() - talk_start
        else:
            talk_s = 0
        return call_id, result, setup_ms or 0, talk_s
