import socket
import uuid
import time


class SIPManager:
    """Utility to build and send simple SIP requests."""

    def __init__(
        self,
        remote_ip,
        remote_port=5060,
        protocol="UDP",
        interval=60,
        timeout=2,
        src_ip="0.0.0.0",
        src_port=5060,
        user="dimitri",
    ):
        self.remote_ip = remote_ip
        self.remote_port = remote_port
        self.protocol = protocol.upper()
        self.interval = interval
        self.timeout = timeout
        self.src_ip = src_ip
        self.src_port = src_port
        self.user = user

    def _new_call(self):
        call_id = str(uuid.uuid4())
        branch = "z9hG4bK" + call_id.replace("-", "")
        return call_id, branch

    def build_options(self):
        call_id, branch = self._new_call()
        msg = (
            f"OPTIONS sip:{self.remote_ip} SIP/2.0\r\n"
            f"Via: SIP/2.0/{self.protocol} {self.src_ip}:{self.src_port};branch={branch}\r\n"
            f"Max-Forwards: 70\r\n"
            f"From: <sip:{self.user}@{self.src_ip}>;tag={self.user}\r\n"
            f"To: <sip:{self.remote_ip}>\r\n"
            f"Call-ID: {call_id}\r\n"
            f"CSeq: 1 OPTIONS\r\n"
            f"Contact: <sip:{self.user}@{self.src_ip}:{self.src_port}>\r\n"
            f"Content-Length: 0\r\n\r\n"
        )
        return msg

    def build_invite(self):
        call_id, branch = self._new_call()
        msg = (
            f"INVITE sip:{self.remote_ip} SIP/2.0\r\n"
            f"Via: SIP/2.0/{self.protocol} {self.src_ip}:{self.src_port};branch={branch}\r\n"
            f"Max-Forwards: 70\r\n"
            f"From: <sip:{self.user}@{self.src_ip}>;tag={self.user}\r\n"
            f"To: <sip:{self.remote_ip}>\r\n"
            f"Call-ID: {call_id}\r\n"
            f"CSeq: 1 INVITE\r\n"
            f"Contact: <sip:{self.user}@{self.src_ip}:{self.src_port}>\r\n"
            f"Content-Type: application/sdp\r\n"
            f"Content-Length: 0\r\n\r\n"
        )
        return msg

    def send_request(self, method="OPTIONS", repeat=1):
        """Send a SIP request and parse the response.

        Parameters
        ----------
        method : str
            Method to send ("OPTIONS" or "INVITE").
        repeat : int or None
            Number of times to send the request. ``None`` sends forever.

        Returns
        -------
        dict or None
            Parsed response information or ``None`` on timeout.
        """
        method = method.upper()
        builder = self.build_options if method == "OPTIONS" else self.build_invite
        last_response = None
        count = repeat
        while True:
            msg = builder().encode()
            if self.protocol == "TCP":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                try:
                    sock.connect((self.remote_ip, self.remote_port))
                    sock.sendall(msg)
                    data = sock.recv(4096)
                    addr = (self.remote_ip, self.remote_port)
                except socket.timeout:
                    data = b""
                    addr = (self.remote_ip, self.remote_port)
                finally:
                    sock.close()
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.timeout)
                try:
                    sock.sendto(msg, (self.remote_ip, self.remote_port))
                    data, addr = sock.recvfrom(4096)
                except socket.timeout:
                    data = b""
                    addr = (self.remote_ip, self.remote_port)
                finally:
                    sock.close()

            if data:
                text = data.decode(errors="ignore")
                first_line = text.splitlines()[0] if text else ""
                parts = first_line.split(" ", 2)
                status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
                reason = parts[2] if len(parts) > 2 else ""
                last_response = {"status": status, "reason": reason, "raw": text, "from": addr}
            else:
                last_response = None

            if count is None:
                time.sleep(self.interval)
                continue
            count -= 1
            if count <= 0:
                break
            time.sleep(self.interval)
        return last_response
