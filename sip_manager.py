import logging
import socket
import time
import uuid

logger = logging.getLogger("socket_handler")


def _status_from_response(data: bytes):
    """Devuelve (codigo, razon) a partir de la primera línea SIP."""
    try:
        line0 = data.decode(errors="ignore").splitlines()[0]
        parts = line0.split(" ", 2)
        code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
        reason = parts[2] if len(parts) > 2 else ""
        return code, reason
    except Exception:
        return None, ""


def _build_options(dst_host: str, local_ip: str, local_port: int, user: str, cseq: int) -> bytes:
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
    return msg.encode()


class SIPManager:
    def __init__(self, protocol: str = "udp"):
        self.protocol = protocol

    def _open_connected_udp(self, dst_host: str, dst_port: int, bind_ip: str | None):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Bindea a IP local (si se indica) o 0.0.0.0 con puerto efímero
        s.bind(((bind_ip or "0.0.0.0"), 0))
        # Conecta para fijar local_ip:local_port reales
        s.connect((dst_host, dst_port))
        local_ip, local_port = s.getsockname()
        return s, local_ip, local_port

    def send_request(
        self,
        dst_host: str,
        dst_port: int = 5060,
        timeout: float = 2.0,
        bind_ip: str | None = None,
        cseq: int = 1,
        user: str = "dimitri",
    ):
        if self.protocol != "udp":
            raise NotImplementedError("Solo UDP por ahora.")

        s, local_ip, local_port = self._open_connected_udp(dst_host, dst_port, bind_ip)
        s.settimeout(timeout)

        payload = _build_options(dst_host, local_ip, local_port, user, cseq)

        t0 = time.time()
        logger.info(f"Abriendo socket UDP a {dst_host}:{dst_port}")
        s.send(payload)
        logger.info(f"UDP enviado a {dst_host}:{dst_port} sent-by={local_ip}:{local_port}")
        try:
            data = s.recv(2048)
            rtt_ms = int((time.time() - t0) * 1000)
            logger.info(f"UDP recibido de {dst_host}:{dst_port}")
            code, reason = _status_from_response(data)
            return code, reason, rtt_ms
        except socket.timeout:
            return None, None, None
        finally:
            logger.info("Socket UDP cerrado")
            s.close()