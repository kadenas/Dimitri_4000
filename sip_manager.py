import socket
import uuid
import time
import logging
import ipaddress

from socket_handler import (
    open_udp_socket,
    open_tcp_socket,
    udp_send,
    udp_receive,
    tcp_send,
    tcp_receive,
)
from logging_conf import setup_logging


setup_logging()
logger = logging.getLogger(__name__)


def detect_src_ip(dst_host, dst_port):
    """Detect the outgoing source IP for the given destination."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((dst_host, dst_port))
        return s.getsockname()[0]
    except OSError:
        return "0.0.0.0"
    finally:
        s.close()


class SIPManager:
    """Utility to build and send simple SIP requests."""

    def __init__(
        self,
        remote_ip,
        remote_port=5060,
        protocol="UDP",
        interval=60,
        timeout=2,
        retries=3,
        src_ip="0.0.0.0",
        src_port=0,
        user="dimitri",
    ):
        ipaddress.ip_address(remote_ip)
        self.remote_ip = remote_ip
        self.remote_port = remote_port
        self.protocol = protocol.upper()
        self.interval = interval
        self.timeout = timeout
        self.retries = retries
        self.src_ip = src_ip or "0.0.0.0"
        self.src_port = src_port
        self.user = user
        self.stats = {
            "OPTIONS": {"sent": 0, "ok": 0, "timeout": 0, "latencies": []},
            "INVITE": {"sent": 0, "ok": 0, "timeout": 0, "latencies": []},
        }
        if self.src_ip in ("0.0.0.0", ""):
            self.src_ip = detect_src_ip(self.remote_ip, self.remote_port)

    def _new_call(self):
        call_id = str(uuid.uuid4())
        branch = "z9hG4bK" + call_id.replace("-", "")
        return call_id, branch

    def build_options(self, src_ip=None, src_port=0, cseq=1):
        src_ip = src_ip or self.src_ip
        call_id, branch = self._new_call()
        msg = (
            f"OPTIONS sip:{self.remote_ip} SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP {src_ip}:{src_port};branch={branch};rport\r\n"
            "Max-Forwards: 70\r\n"
            f"From: <sip:{self.user}@{src_ip}>;tag={self.user}\r\n"
            f"To: <sip:{self.remote_ip}>\r\n"
            f"Call-ID: {call_id}\r\n"
            f"CSeq: {cseq} OPTIONS\r\n"
            f"Contact: <sip:{self.user}@{src_ip}>\r\n"
            "User-Agent: Dimitri-4000/0.1\r\n"
            "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE\r\n"
            "Accept: application/sdp\r\n"
            "Content-Length: 0\r\n\r\n"
        )
        return msg

    def send_options(self, cseq=1):
        if self.protocol != "UDP":
            raise NotImplementedError("TCP no implementado")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        bind_ip = self.src_ip if self.src_ip not in ("0.0.0.0", "") else "0.0.0.0"
        start = time.time()
        try:
            if self.timeout is not None:
                sock.settimeout(self.timeout)
            sock.bind((bind_ip, 0))
            sock.connect((self.remote_ip, self.remote_port))
            local_ip, local_port = sock.getsockname()
            msg = self.build_options(local_ip, local_port, cseq).encode()
            logger.info(
                "Enviando OPTIONS (CSeq=%s) a %s:%s sent-by=%s:%s",
                cseq,
                self.remote_ip,
                self.remote_port,
                local_ip,
                local_port,
            )
            sock.send(msg)
            data = sock.recv(2048)
            rtt = (time.time() - start) * 1000
            text = data.decode(errors="ignore")
            first = text.splitlines()[0] if text else ""
            parts = first.split(" ", 2)
            status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
            reason = parts[2] if len(parts) > 2 else ""
            return status, reason, rtt, text
        except (socket.timeout, OSError):
            rtt = (time.time() - start) * 1000
            return None, "", rtt, ""
        finally:
            sock.close()

    def build_invite(self, headers=None):
        """Build an INVITE request.

        Parameters
        ----------
        headers : dict or str, optional
            Custom headers to include or override. When a string is provided it
            should contain ``Header: value`` lines separated by newlines.

        Returns
        -------
        str
            Complete SIP INVITE message.

        Raises
        ------
        ValueError
            If any mandatory header is missing.
        """
        call_id, branch = self._new_call()
        base_headers = {
            "Via": f"SIP/2.0/{self.protocol} {self.src_ip}:{self.src_port};branch={branch}",
            "Max-Forwards": "70",
            "From": f"<sip:{self.user}@{self.src_ip}>;tag={self.user}",
            "To": f"<sip:{self.remote_ip}>",
            "Call-ID": call_id,
            "CSeq": "1 INVITE",
            "Contact": f"<sip:{self.user}@{self.src_ip}:{self.src_port}>",
            "Content-Type": "application/sdp",
            "Content-Length": "0",
        }

        custom = {}
        if headers:
            if isinstance(headers, str):
                lines = [line.strip() for line in headers.splitlines() if line.strip()]
                for line in lines:
                    if ":" in line:
                        k, v = line.split(":", 1)
                        custom[k.strip()] = v.strip()
            elif isinstance(headers, dict):
                custom = {k.strip(): v for k, v in headers.items()}

        # Override defaults and add any additional headers
        base_headers.update(custom)

        mandatory = [
            "Via",
            "From",
            "To",
            "Call-ID",
            "CSeq",
            "Max-Forwards",
            "Contact",
            "Content-Length",
        ]
        for hdr in mandatory:
            if not base_headers.get(hdr):
                raise ValueError(f"Missing mandatory header: {hdr}")

        start_line = f"INVITE sip:{self.remote_ip} SIP/2.0\r\n"
        header_lines = "".join(f"{k}: {v}\r\n" for k, v in base_headers.items())
        return start_line + header_lines + "\r\n"

    def send_request(self, method="OPTIONS", repeat=1, headers=None, retries=None):
        """Send a SIP request and parse the response.

        Parameters
        ----------
        method : str
            Method to send ("OPTIONS" or "INVITE").
        repeat : int or None
            Number of times to send the request. ``None`` sends forever.
        headers : dict or str, optional
            Additional headers for INVITE requests. Can override default
            headers when provided.
        retries : int or None
            Number of times to retry on timeout or network error for each
            request. ``None`` uses the value configured on the instance.

        Returns
        -------
        tuple
            A tuple ``(response, latency)`` where ``response`` is a dict with
            parsed information or ``None`` on timeout, and ``latency`` is the
            elapsed time in seconds for the last request.
        """
        method = method.upper()
        builder = self.build_options if method == "OPTIONS" else lambda: self.build_invite(headers)
        last_response = None
        count = repeat
        retries = self.retries if retries is None else retries
        while True:
            msg = builder().encode()
            logger.info("Enviando %s a %s:%s", method, self.remote_ip, self.remote_port)
            logger.debug("Mensaje enviado: %s", msg.decode(errors="ignore"))
            attempt = 0
            data = b""
            addr = (self.remote_ip, self.remote_port)
            while attempt <= retries:
                start = time.time()
                try:
                    if self.protocol == "TCP":
                        with open_tcp_socket(
                            self.remote_ip,
                            self.remote_port,
                            local_port=self.src_port,
                            timeout=self.timeout,
                        ) as sock:
                            tcp_send(sock, msg)
                            data = tcp_receive(sock)
                            addr = sock.getpeername()
                    else:
                        with open_udp_socket(
                            self.remote_ip,
                            self.remote_port,
                            local_port=self.src_port,
                            timeout=self.timeout,
                        ) as (sock, raddr):
                            udp_send(sock, msg, raddr)
                            data, addr = udp_receive(sock)
                    break
                except socket.timeout:
                    attempt += 1
                    logger.error(
                        "Timeout esperando respuesta %s de %s:%s (intento %s/%s)",
                        self.protocol,
                        self.remote_ip,
                        self.remote_port,
                        attempt,
                        retries + 1,
                    )
                except OSError as exc:
                    attempt += 1
                    logger.error(
                        "Error de red %s en intento %s/%s: %s",
                        self.protocol,
                        attempt,
                        retries + 1,
                        exc,
                    )
            latency = time.time() - start
            stats = self.stats[method]
            stats["sent"] += 1
            stats["latencies"].append(latency)
            if data:
                text = data.decode(errors="ignore")
                first_line = text.splitlines()[0] if text else ""
                parts = first_line.split(" ", 2)
                status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
                reason = parts[2] if len(parts) > 2 else ""
                last_response = {"status": status, "reason": reason, "raw": text, "from": addr}
                if status == 200:
                    stats["ok"] += 1
            else:
                last_response = None
                stats["timeout"] += 1

            if count is None:
                time.sleep(self.interval)
                continue
            count -= 1
            if count <= 0:
                break
            time.sleep(self.interval)
        return last_response, latency

    def get_stats(self, method):
        method = method.upper()
        stats = self.stats.get(method, {})
        sent = stats.get("sent", 0)
        ok = stats.get("ok", 0)
        timeout = stats.get("timeout", 0)
        success_rate = ok / sent if sent else 0.0
        latencies = stats.get("latencies", [])
        avg_latency = sum(latencies) / len(latencies) if latencies else 0.0
        return {
            "sent": sent,
            "ok": ok,
            "timeout": timeout,
            "success_rate": success_rate,
            "avg_latency": avg_latency,
        }
