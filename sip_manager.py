import logging
import re
import socket
import threading
import time
import uuid
import hashlib
import secrets
import errno
import random
import string
from dataclasses import dataclass
from typing import Dict, Tuple
from rtp import RtpSession
from sdp import (
    build_sdp,
    parse_sdp,
    CODEC_NAME_FROM_PT,
    parse_direction_from_sdp,
    direction_to_flags,
    flags_to_direction,
    intersect_answer,
    DIRECTION_SET,
)
from sdp_utils import parse_sdp_ip_port

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


def strip_brackets(uri: str | None) -> str:
    """Return the URI without surrounding angle brackets."""

    if not uri:
        return ""
    value = uri.strip()
    if "<" in value and ">" in value:
        value = value.split("<", 1)[1].split(">", 1)[0]
    return value.strip().lstrip("<").rstrip(">").strip()


def bracket(uri: str | None) -> str:
    """Return the URI wrapped in angle brackets if not empty."""

    clean = strip_brackets(uri)
    return f"<{clean}>" if clean else ""


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
    dst_host: str,
    local_ip: str,
    local_port: int,
    user: str,
    cseq: int,
    extra_headers: list[str] | None = None,
) -> tuple[str, bytes]:
    """Construye un mensaje OPTIONS y devuelve (call-id, bytes)."""
    call_id = str(uuid.uuid4())
    branch = "z9hG4bK" + call_id.replace("-", "")
    sent_by = f"{local_ip}:{local_port}"  # SIEMPRE con puerto real
    lines = [
        f"OPTIONS sip:{dst_host} SIP/2.0\r\n",
        f"Via: SIP/2.0/UDP {sent_by};branch={branch};rport\r\n",
        "Max-Forwards: 70\r\n",
        f"From: <sip:{user}@{local_ip}>;tag={user}\r\n",
        f"To: <sip:{dst_host}>\r\n",
        f"Call-ID: {call_id}\r\n",
        f"CSeq: {cseq} OPTIONS\r\n",
        f"Contact: <sip:{user}@{local_ip}>\r\n",
        "User-Agent: Dimitri-4000/0.1\r\n",
        "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE\r\n",
        "Accept: application/sdp\r\n",
    ]
    for header in extra_headers or []:
        lines.append(f"{header}\r\n")
    lines.append("Content-Length: 0\r\n\r\n")
    return call_id, "".join(lines).encode()


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
    extra_headers: list[str] | None = None,
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
    )
    if use_pai and pai:
        msg += f"P-Preferred-Identity: <{pai}>\r\n"
    if use_pai_asserted and pai:
        msg += f"P-Asserted-Identity: <{pai}>\r\n"
    if auth_header:
        msg += f"{auth_header[0]}: {auth_header[1]}\r\n"
    if extra_headers:
        for header in extra_headers:
            msg += f"{header}\r\n"
    msg += (
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


def build_uac_bye_request(
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


def build_trying(headers: dict) -> bytes:
    """Shortcut to build a 100 Trying response."""
    return build_response(100, "Trying", headers)


def build_ringing(headers: dict) -> bytes:
    """Shortcut to build a 180 Ringing response."""
    return build_response(180, "Ringing", headers)


def build_200(headers: dict, body: bytes | str = b"") -> bytes:
    """Shortcut to build a 200 OK response."""
    return build_response(200, "OK", headers, body)


def build_487(headers: dict) -> bytes:
    """Shortcut to build a 487 Request Terminated response."""
    return build_response(487, "Request Terminated", headers)

@dataclass
class Dialog:
    """Simple representation of an established SIP dialog."""

    call_id: str
    local_uri: str
    remote_uri: str
    local_tag: str
    remote_tag: str
    route_set: list[str]
    remote_target: str
    local_contact: str | None
    cseq_local: int
    cseq_remote: int
    sock: socket.socket | None
    local_ip: str
    local_port: int
    role: str
    dst: tuple[str, int] | None = None
    rtp: RtpSession | None = None


def build_bye_request(
    dlg: Dialog, local_ip: str, local_port: int, transport: str = "UDP"
) -> str:
    """Return a properly formatted BYE request for the given dialog."""

    branch = "z9hG4bK" + uuid.uuid4().hex
    request_uri = strip_brackets(dlg.remote_target)
    from_uri = bracket(dlg.local_uri)
    to_uri = bracket(dlg.remote_uri)
    from_header = from_uri
    if dlg.local_tag:
        from_header = f"{from_header};tag={dlg.local_tag}" if from_header else f";tag={dlg.local_tag}"
    to_header = to_uri
    if dlg.remote_tag:
        to_header = f"{to_header};tag={dlg.remote_tag}" if to_header else f";tag={dlg.remote_tag}"
    cseq = dlg.cseq_local + 1
    dlg.cseq_local = cseq
    lines = [
        f"BYE {request_uri} SIP/2.0\r\n",
        f"Via: SIP/2.0/{transport.upper()} {local_ip}:{local_port};branch={branch};rport\r\n",
        "Max-Forwards: 70\r\n",
        f"From: {from_header}\r\n",
        f"To: {to_header}\r\n",
        f"Call-ID: {dlg.call_id}\r\n",
        f"CSeq: {cseq} BYE\r\n",
    ]
    for route in dlg.route_set:
        if route:
            lines.append(f"Route: {route}\r\n")
    contact_uri = bracket(dlg.local_contact)
    if contact_uri:
        lines.append(f"Contact: {contact_uri}\r\n")
    lines.append("User-Agent: Dimitri-4000/0.1\r\n")
    lines.append("Content-Length: 0\r\n\r\n")
    return "".join(lines)


def build_bye(dialog: dict) -> bytes:
    """Backward-compatible helper to build a BYE from legacy dialog dicts."""

    local_ip = dialog.get("local_ip", "0.0.0.0")
    try:
        local_port = int(dialog.get("local_port", 0))
    except (TypeError, ValueError):
        local_port = 0
    try:
        next_cseq = int(dialog.get("our_next_cseq", 1))
    except (TypeError, ValueError):
        next_cseq = 1
    try:
        remote_cseq = int(str(dialog.get("their_cseq_invite", 0)))
    except (TypeError, ValueError):
        remote_cseq = 0
    dlg = Dialog(
        call_id=str(dialog.get("call_id", "")),
        local_uri=strip_brackets(dialog.get("to_uri")),
        remote_uri=strip_brackets(dialog.get("from_uri")),
        local_tag=str(dialog.get("local_tag", "")),
        remote_tag=str(dialog.get("remote_tag", "")),
        route_set=list(dialog.get("route_set") or []),
        remote_target=strip_brackets(
            dialog.get("peer_uri")
            or dialog.get("remote_target")
            or dialog.get("to_uri")
            or ""
        ),
        local_contact=strip_brackets(
            dialog.get("local_contact")
            or (f"sip:dimitri@{local_ip}:{local_port}" if local_ip else "")
        ),
        cseq_local=max(next_cseq - 1, 0),
        cseq_remote=remote_cseq,
        sock=None,
        local_ip=local_ip,
        local_port=local_port,
        role=str(dialog.get("role", "uas")),
        dst=dialog.get("peer_addr"),
        rtp=dialog.get("rtp"),
    )
    bye_text = build_bye_request(dlg, local_ip, local_port)
    dialog["our_next_cseq"] = dlg.cseq_local + 1
    return bye_text.encode()


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
    def __init__(
        self,
        protocol: str = "udp",
        sock: socket.socket | None = None,
        bind_ip: str = "0.0.0.0",
        src_port: int = 0,
        logger: logging.Logger | None = None,
    ):
        self.protocol = protocol
        self.logger = logger or logging.getLogger("socket_handler")
        if sock is None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            if src_port:
                sock.bind((bind_ip, src_port))
            self._own_sock = True
        else:
            self._own_sock = False
        self.sock = sock
        self.sock.settimeout(2.0)
        # dialogs indexed by Call-ID for UAC and UAS roles
        self.uac_dialogs: Dict[str, Dialog] = {}
        self.uas_dialogs: Dict[str, Dialog] = {}
        self.cseq_invite = 1
        self.cseq_bye = 1
        self.cseq_options = 1
        self.early = False
        self.confirmed = False
        self.failed = False
        self.cancel_requested = False
        self.ring_timer: threading.Timer | None = None
        self._current_call: dict | None = None
        self._uac_lock = threading.Lock()

    def _new_cseq(self) -> int:
        """Return a random initial CSeq for new dialogs."""
        return random.randint(100, 10000)

    def _new_tag(self) -> str:
        """Return a simple random tag for dialog identifiers."""
        return ''.join(random.choice(string.hexdigits.lower()) for _ in range(8))

    def _local_ip_port(
        self,
        sock: socket.socket,
        dst_host: str | None = None,
        dst_port: int | None = None,
    ) -> tuple[str, int]:
        ip, port = sock.getsockname()
        if ip == "0.0.0.0" and dst_host and dst_port:
            try:
                sock.connect((dst_host, dst_port))
                ip = sock.getsockname()[0]
                sock.connect(("0.0.0.0", 0))
            except Exception:
                pass
        return ip, port

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
        extra_headers: list[str] | None = None,
    ):
        if self.protocol != "udp":
            raise NotImplementedError("Solo UDP por ahora.")

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if bind_ip or bind_port:
            try:
                s.bind((bind_ip or "0.0.0.0", bind_port))
            except OSError as e:
                logger.error(
                    f"No se pudo bindear UDP en {bind_ip or '0.0.0.0'}:{bind_port}: {e}"
                )
                s.close()
                raise

        s.settimeout(timeout)

        s.connect((dst_host, dst_port))
        local_ip, local_port = s.getsockname()
        _call_id, payload = build_options(
            dst_host, local_ip, local_port, user, cseq, extra_headers=extra_headers
        )

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

    def _clear_ring_timer(self):
        if self.ring_timer:
            try:
                self.ring_timer.cancel()
            except Exception:
                pass
            self.ring_timer = None

    def _schedule_ring_timer(self, ring_timeout: float):
        self._clear_ring_timer()
        if ring_timeout > 0:
            timer = threading.Timer(ring_timeout, self._on_ring_timeout)
            timer.daemon = True
            self.ring_timer = timer
            timer.start()

    def _reset_call_state(self):
        self._clear_ring_timer()
        self.early = False
        self.confirmed = False
        self.failed = False
        self.cancel_requested = False
        self._current_call = None

    def _on_ring_timeout(self):
        ctx = self._current_call
        if not ctx:
            return
        if self.confirmed or self.failed:
            return
        self.cancel_requested = True
        logger.info(
            "Ring timeout alcanzado, enviando CANCEL call_id=%s",
            ctx.get("call_id"),
        )
        self._send_cancel()

    def _send_cancel(self):
        ctx = self._current_call
        if not ctx or self.confirmed:
            return
        if ctx.get("cancel_sent"):
            return
        cancel = build_cancel(
            ctx["request_uri"],
            ctx["to_uri"],
            ctx["local_ip"],
            ctx["local_port"],
            ctx["from_uri"],
            ctx["from_display"],
            ctx["call_id"],
            ctx["invite_cseq"],
            ctx["tag"],
            ctx["branch"],
            ctx["contact_user"],
        )
        try:
            ctx["sock"].send(cancel)
        except OSError as e:
            if getattr(e, "errno", None) == errno.ECONNREFUSED:
                logger.error(
                    "Destino no escucha en %s:%s",
                    ctx.get("dst_host"),
                    ctx.get("dst_port"),
                )
                return
            raise
        logger.info("Enviado CANCEL call_id=%s", ctx["call_id"])
        self._clear_ring_timer()
        ctx["cancel_sent"] = True
        ctx["cancel_deadline"] = time.monotonic() + 5

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
        codecs: list[tuple[int, str]] | None = None,
        sdp_offer: bytes | str | None = None,
        rtp_port: int = 40000,
        rtp_port_forced: bool = False,
        rtcp: bool = False,
        tone_hz: int | None = None,
        send_silence: bool = False,
        symmetric: bool = False,
        save_wav: str | None = None,
        stats_interval: float = 2.0,
        extra_headers: list[str] | None = None,
        sdp_direction: str = "sendrecv",
        sdp_media_extras: list[str] | None = None,
        sdp_session_extras: list[str] | None = None,
    ) -> tuple[str, str, int, float]:
        if self.protocol != "udp":
            raise NotImplementedError("Solo UDP por ahora.")

        self._uac_lock.acquire()
        self._reset_call_state()
        owned_socket = False
        prev_timeout = None
        if self.sock:
            s = self.sock
            prev_timeout = s.gettimeout()
            try:
                s.connect((dst_host, dst_port))
            except OSError as e:
                if getattr(e, "errno", None) == errno.ECONNREFUSED:
                    logger.error(
                        f"Destino no escucha en {dst_host}:{dst_port}"
                    )
                raise
            local_ip, local_port = self._local_ip_port(s, dst_host, dst_port)
            s.settimeout(0.5)
        else:
            s, local_ip, local_port = self._open_connected_udp(
                dst_host, dst_port, bind_ip, bind_port
            )
            local_ip, local_port = self._local_ip_port(s, dst_host, dst_port)
            s.settimeout(0.5)
            owned_socket = True

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
        if cseq_start and self.cseq_invite < cseq_start:
            self.cseq_invite = cseq_start
        invite_cseq = self.cseq_invite
        self.cseq_invite += 1
        auth_username = auth_username or auth_user or from_user
        auth_state = {"nc": 0, "realm": auth_realm, "nonce": None, "opaque": None, "qop": "auth", "proxy": False}

        call_id = str(uuid.uuid4())
        # unique branch per call but keep it short for nicer logs
        branch = "z9hG4bK" + uuid.uuid4().hex[:16]
        tag = uuid.uuid4().hex[:8]
        codecs = codecs or [(0, "PCMU"), (8, "PCMA")]
        pt_list = [pt for pt, _ in codecs]
        extra_headers = list(extra_headers or [])
        session_extras = list(sdp_session_extras or [])
        media_extras = list(sdp_media_extras or [])
        offer_pref = (sdp_direction or "sendrecv").lower()
        if offer_pref not in DIRECTION_SET:
            logger.warning("Dirección SDP inválida %s; usando sendrecv", offer_pref)
            offer_pref = "sendrecv"
        if sdp_offer is not None:
            sdp_text = sdp_offer.decode() if isinstance(sdp_offer, bytes) else str(sdp_offer)
        else:
            sdp_text = build_sdp(
                local_ip,
                rtp_port,
                codecs,
                session_extras=session_extras,
                media_extras=media_extras,
                direction=offer_pref,
            )
        offer_direction = parse_direction_from_sdp(sdp_text.splitlines())
        logger.info(
            "Offer SDP PTs=%s dir=%s; supported locally=[0,8]",
            pt_list,
            offer_direction,
        )
        if extra_headers:
            self.logger.info("Extra headers: %s", " | ".join(extra_headers))
        else:
            self.logger.info("Extra headers: -")
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
            sdp_text,
            from_display=from_display,
            contact_user=contact_user,
            pai=pai,
            use_pai=use_pai,
            use_pai_asserted=use_pai_asserted,
            extra_headers=extra_headers,
        )

        self._current_call = {
            "sock": s,
            "request_uri": request_uri,
            "to_uri": to_uri,
            "local_ip": local_ip,
            "local_port": local_port,
            "from_uri": from_uri,
            "from_display": from_display,
            "call_id": call_id,
            "invite_cseq": invite_cseq,
            "tag": tag,
            "branch": branch,
            "contact_user": contact_user,
            "dst_host": dst_host,
            "dst_port": dst_port,
            "cancel_sent": False,
            "cancel_deadline": None,
        }
        self.cancel_requested = False

        logger.info(
            f"Enviando INVITE (CSeq={invite_cseq}) a {dst_host}:{dst_port} sent-by={local_ip}:{local_port}"
        )
        try:
            s.send(invite)
        except OSError as e:
            if getattr(e, "errno", None) == errno.ECONNREFUSED:
                logger.error(
                    f"Destino no escucha en {dst_host}:{dst_port}"
                )
            raise
        self._schedule_ring_timer(ring_timeout)
        t_start = time.monotonic()
        t1 = 0.5
        next_resend = t_start + t1
        ring_deadline = t_start + ring_timeout
        canceled = False
        cancel_deadline = None
        remote_target = request_uri
        route_set: list[str] = []
        to_header = f"<{to_uri}>"
        # retransmission control
        MAX_RETX = 1
        retries = 0
        got_provisional = False
        
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
            bye = build_uac_bye_request(
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
                except OSError as e:
                    if getattr(e, "errno", None) == errno.ECONNREFUSED:
                        logger.error(
                            f"Destino no escucha en {dst_host}:{dst_port}"
                        )
                        return cseq
                    raise
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
                        bye = build_uac_bye_request(
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
                    self.cancel_requested = False
                    break
            return cseq

        setup_ms = None
        result = "timeout"

        call_established = False
        talk_start = None
        try:
            while True:
                now = time.monotonic()
                if self.cancel_requested and not canceled:
                    canceled = True
                    ctx = self._current_call or {}
                    cancel_deadline = ctx.get("cancel_deadline")
                if (
                    not canceled
                    and not self.confirmed
                    and ring_timeout > 0
                    and now >= ring_deadline
                ):
                    self.cancel_requested = True
                    self._send_cancel()
                    canceled = True
                    ctx = self._current_call or {}
                    cancel_deadline = ctx.get("cancel_deadline")
                    if cancel_deadline is None:
                        cancel_deadline = now + 5
                    continue

                if canceled and cancel_deadline and now >= cancel_deadline:
                    result = "canceled-timeout"
                    self.failed = True
                    break

                try:
                    data = s.recv(4096)
                except socket.timeout:
                    now = time.monotonic()
                    if (
                        not canceled
                        and not got_provisional
                        and now >= next_resend
                        and retries < MAX_RETX
                    ):
                        try:
                            s.send(invite)
                        except OSError as e:
                            if getattr(e, "errno", None) == errno.ECONNREFUSED:
                                logger.error(
                                    f"Destino no escucha en {dst_host}:{dst_port}"
                                )
                                raise
                            raise
                        t1 = min(t1 * 2, 4.0)
                        next_resend = now + t1
                        retries += 1
                        continue
                    if not got_provisional:
                        result = "timeout"
                        self.failed = True
                        break
                    continue
                except OSError as e:
                    if getattr(e, "errno", None) == errno.ECONNREFUSED:
                        logger.error(
                            f"Destino no escucha en {dst_host}:{dst_port}"
                        )
                        raise
                    raise

                code, reason = status_from_response(data)
                start, headers = parse_headers(data)
                cseq_hdr = headers.get("cseq", "")
                if code is not None and 100 <= code < 200:
                    got_provisional = True
                    if code in (180, 183):
                        self.early = True

                if canceled and not self.confirmed:
                    if code == 200 and "CANCEL" in cseq_hdr.upper():
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
                        self._clear_ring_timer()
                        self.failed = True
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
                            sdp_text,
                            from_display=from_display,
                            contact_user=contact_user,
                            pai=pai,
                            use_pai=use_pai,
                            use_pai_asserted=use_pai_asserted,
                            auth_header=(hdr_name, auth_val),
                            extra_headers=extra_headers,
                        )
                        self._current_call.update(
                            {
                                "branch": branch,
                                "invite_cseq": invite_cseq,
                                "cancel_sent": False,
                                "cancel_deadline": None,
                            }
                        )
                        logger.info("Reenviando INVITE con autenticacion Digest")
                        try:
                            s.send(invite)
                        except OSError as e:
                            if getattr(e, "errno", None) == errno.ECONNREFUSED:
                                logger.error(
                                    f"Destino no escucha en {dst_host}:{dst_port}"
                                )
                                raise
                            raise
                        self._schedule_ring_timer(ring_timeout)
                        t_start = time.monotonic()
                        t1 = 0.5
                        next_resend = t_start + t1
                        ring_deadline = t_start + ring_timeout
                        auth_state["invite_auth_done"] = True
                        continue

                if code == 200:
                    if "CANCEL" in cseq_hdr.upper():
                        logger.info("200 OK al CANCEL (ignorado)")
                        continue
                    setup_ms = int((time.monotonic() - t_start) * 1000)
                    logger.info(f"200 OK en {setup_ms} ms")
                    to_header = headers.get("to", to_header)
                    body = b""
                    if b"\r\n\r\n" in data:
                        body = data.split(b"\r\n\r\n", 1)[1]
                    sdp_info = parse_sdp(body)
                    try:
                        remote_ip, remote_port = parse_sdp_ip_port(body)
                    except ValueError:
                        remote_ip = sdp_info.get("ip") or dst_host
                        remote_port = sdp_info.get("audio_port") or rtp_port
                    pts = sdp_info.get("pts") or []
                    negotiated_pt = next((pt for pt in pts if pt in pt_list), None)
                    codec_name = None
                    if negotiated_pt is not None:
                        codec_name = sdp_info.get("rtpmap", {}).get(
                            negotiated_pt,
                            CODEC_NAME_FROM_PT.get(negotiated_pt, str(negotiated_pt)),
                        )
                    logger.info(
                        "Negotiated codec: %s (PT=%s)",
                        codec_name or "-",
                        negotiated_pt if negotiated_pt is not None else "-",
                    )
                    remote_dir = sdp_info.get("direction", "sendrecv") or "sendrecv"
                    if remote_dir not in DIRECTION_SET:
                        remote_dir = "sendrecv"
                    remote_send, remote_recv = direction_to_flags(remote_dir)
                    local_send = remote_recv
                    local_recv = remote_send
                    local_dir = flags_to_direction(local_send, local_recv)
                    logger.info(
                        "SDP negotiated dir: offer=%s, answer=%s -> effective: %s local / %s remote",
                        offer_direction,
                        remote_dir,
                        local_dir,
                        remote_dir,
                    )
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
                    self.confirmed = True
                    self._clear_ring_timer()
                    ctx = self._current_call or {}
                    ctx["remote_target"] = remote_target
                    ctx["to_header"] = to_header
                    if negotiated_pt is None:
                        s.send(ack)
                        logger.warning(
                            "unsupported negotiated codec pts=%s local=%s",
                            pts,
                            pt_list,
                        )
                        invite_cseq = send_bye(invite_cseq + 1)
                        result = "unsupported-codec"
                        break
                    rtp = RtpSession(
                        local_ip,
                        rtp_port,
                        negotiated_pt,
                        symmetric=symmetric,
                        save_wav=save_wav,
                        forced=rtp_port_forced,
                    )
                    rtp.rtcp = rtcp
                    rtp.tone_hz = tone_hz
                    rtp.send_silence = send_silence and not tone_hz
                    rtp.stats_interval = stats_interval
                    rtp.set_sending(local_send)
                    rtp.set_receiving(local_recv)
                    logger.info(
                        "Starting RTP to %s:%s", remote_ip, remote_port
                    )
                    rtp.start(remote_ip, remote_port)
                    s.send(ack)
                    call_established = True
                    if self.cancel_requested:
                        invite_cseq = send_bye(invite_cseq + 1)
                        self._safe_stop_rtp(self.uac_dialogs.get(call_id))
                        self.uac_dialogs.pop(call_id, None)
                        result = "canceled-after-200"
                        break
                    # register dialog for possible later BYE from GUI/load
                    remote_tag = ""
                    if "tag=" in to_header:
                        remote_tag = to_header.split("tag=")[1].split(";", 1)[0]
                    try:
                        remote_cseq = int((headers.get("cseq") or "0").split()[0])
                    except (ValueError, IndexError):
                        remote_cseq = 0
                    self.uac_dialogs[call_id] = Dialog(
                        call_id=call_id,
                        local_uri=from_uri,
                        remote_uri=to_uri,
                        local_tag=tag,
                        remote_tag=remote_tag,
                        route_set=route_set.copy(),
                        remote_target=remote_target,
                        local_contact=f"sip:{contact_user}@{local_ip}:{local_port}",
                        cseq_local=invite_cseq,
                        cseq_remote=remote_cseq,
                        sock=s,
                        local_ip=local_ip,
                        local_port=local_port,
                        role="uac",
                        dst=(dst_host, dst_port),
                        rtp=rtp,
                    )
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
                                except OSError as e:
                                    if getattr(e, "errno", None) == errno.ECONNREFUSED:
                                        logger.error(
                                            f"Destino no escucha en {dst_host}:{dst_port}"
                                        )
                                        raise
                                    raise
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
                                    self.logger.info(
                                        f"RX BYE call_id={call_id} side=UAC -> sending 200 OK & stopping RTP"
                                    )
                                    self._safe_stop_rtp(self.uac_dialogs.get(call_id))
                                    self.uac_dialogs.pop(call_id, None)
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
                    self._clear_ring_timer()
                    self.failed = True
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
            try:
                self._reset_call_state()
                self.uac_dialogs.pop(call_id, None)
                if owned_socket:
                    s.close()
                else:
                    try:
                        if prev_timeout is not None:
                            s.settimeout(prev_timeout)
                        s.connect(("0.0.0.0", 0))
                    except OSError:
                        pass
                if 'rtp' in locals():
                    rtp.stop()
            finally:
                self._uac_lock.release()

        if talk_start:
            talk_s = time.monotonic() - talk_start
        else:
            talk_s = 0
        return call_id, result, setup_ms or 0, talk_s

    # ------------------------------------------------------------------
    def _safe_stop_rtp(self, d):
        """Stop RTP session stored in dialog if present, ignoring errors."""
        try:
            if isinstance(d, dict):
                rtp = d.get("rtp")
            else:
                rtp = getattr(d, "rtp", None)
            if rtp:
                rtp.stop()
        except Exception:
            pass

    # ------------------------------------------------------------------
    def handle_uas_bye(self, msg: bytes, addr: tuple[str, int]) -> bool:
        """Handle an incoming BYE request on UAS side.

        Sends 200 OK, stops RTP for the dialog and removes it from
        ``uas_dialogs``. Returns ``True`` if a BYE was processed.
        """
        start, headers = parse_headers(msg)
        if not start or not start.startswith("BYE "):
            return False
        call_id = headers.get("call-id", "")
        resp = build_response(
            200,
            "OK",
            {
                "Via": headers.get("via", ""),
                "From": headers.get("from", ""),
                "To": headers.get("to", ""),
                "Call-ID": call_id,
                "CSeq": headers.get("cseq", ""),
            },
        )
        try:
            self.sock.sendto(resp, addr)
        except Exception:
            pass
        dlg = self.uas_dialogs.pop(call_id, None)
        if dlg:
            self._safe_stop_rtp(dlg)
        self.logger.info(
            "UAS: BYE recibido, 200 OK enviado, RTP detenido. call_id=%s",
            call_id,
        )
        return True

    # ------------------------------------------------------------------
    def bye_all(self, role: str, timeout: float = 3.0) -> int:
        """Send BYE to all active dialogs for the given role.

        Parameters
        ----------
        role: str
            Either "uac" or "uas".
        timeout: float
            How long to wait for each 200 OK response.

        Returns
        -------
        int
            Number of BYEs attempted.
        """

        role = role.lower()
        if role == "uas":
            count = 0
            for call_id, dlg in list(self.uas_dialogs.items()):
                try:
                    if isinstance(dlg, Dialog):
                        dst = dlg.dst
                        if not dst:
                            continue
                        src_ip, src_port = self._local_ip_port(
                            self.sock, dst[0], dst[1]
                        )
                        bye_text = build_bye_request(
                            dlg, src_ip, src_port, transport=self.protocol.upper()
                        )
                        req_line = bye_text.split("\r\n", 1)[0]
                        self.logger.info(
                            "UAS BYE -> %s call_id=%s %s CSeq=%s",
                            dst,
                            call_id,
                            req_line,
                            dlg.cseq_local,
                        )
                        self.sock.sendto(bye_text.encode(), dst)
                    else:
                        src_ip, src_port = self._local_ip_port(
                            self.sock, dlg["dst"][0], dlg["dst"][1]
                        )
                        bye = build_bye(dlg)
                        self.logger.info(
                            "UAS BYE -> %s call_id=%s %s",
                            dlg["dst"],
                            call_id,
                            bye.decode(errors="ignore").split("\r\n", 1)[0],
                        )
                        self.sock.sendto(bye, dlg["dst"])
                except Exception as e:
                    self.logger.error(f"UAS BYE error call_id={call_id}: {e}")
                finally:
                    self._safe_stop_rtp(dlg)
                    self.uas_dialogs.pop(call_id, None)
                    count += 1
            return count

        # Default to UAC handling
        dialogs = self.uac_dialogs
        count = 0
        for key, dlg in list(dialogs.items()):
            dst = getattr(dlg, "dst", None)
            try:
                if dst and dlg.sock:
                    src_ip, src_port = self._local_ip_port(dlg.sock, dst[0], dst[1])
                else:
                    src_ip, src_port = dlg.local_ip, dlg.local_port
                bye_text = build_bye_request(
                    dlg, src_ip, src_port, transport=self.protocol.upper()
                )
                req_line = bye_text.split("\r\n", 1)[0]
                self.logger.info(
                    "UAC BYE -> %s call_id=%s %s",
                    dst or dlg.remote_target,
                    dlg.call_id,
                    req_line,
                )
                payload = bye_text.encode()
                if dst and dlg.sock:
                    dlg.sock.sendto(payload, dst)
                elif dlg.sock:
                    dlg.sock.send(payload)
                if dlg.sock:
                    dlg.sock.settimeout(timeout)
                    try:
                        while True:
                            data = dlg.sock.recv(4096)
                            code, _ = status_from_response(data)
                            if code == 200:
                                break
                    except socket.timeout:
                        pass
            except OSError as e:
                self.logger.error(f"UAC BYE error call_id={dlg.call_id}: {e}")
            finally:
                self._safe_stop_rtp(dlg)
                dialogs.pop(key, None)
                count += 1
        return count

    def bye_all_uac(self, timeout: float = 3.0) -> int:
        """Convenience wrapper to BYE all active UAC dialogs."""
        return self.bye_all("uac", timeout)

    def bye_all_uas(self, timeout: float = 3.0) -> int:
        """Convenience wrapper to BYE all active UAS dialogs."""
        return self.bye_all("uas", timeout)

    def uac_active_count(self) -> int:
        """Return number of active UAC dialogs."""
        return len(self.uac_dialogs)

    def uas_active_count(self) -> int:
        """Return number of active UAS dialogs."""
        return len(self.uas_dialogs)

    def active_counts(self) -> dict:
        """Return a dictionary with active dialog counts."""
        return {"uac": len(self.uac_dialogs), "uas": len(self.uas_dialogs)}
