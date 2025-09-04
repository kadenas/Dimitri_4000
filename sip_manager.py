import logging
import socket
import time
import uuid

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
