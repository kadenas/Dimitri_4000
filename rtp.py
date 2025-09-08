import audioop
import logging
import math
import socket
import struct
import threading
import time
import uuid
import errno

logger = logging.getLogger("rtp")


def ulaw_encode(pcm16_bytes: bytes) -> bytes:
    return audioop.lin2ulaw(pcm16_bytes, 2)


def alaw_encode(pcm16_bytes: bytes) -> bytes:
    return audioop.lin2alaw(pcm16_bytes, 2)


def ulaw_decode_to_pcm16(data: bytes) -> bytes:
    return audioop.ulaw2lin(data, 2)


def alaw_decode_to_pcm16(data: bytes) -> bytes:
    return audioop.alaw2lin(data, 2)


def build_rtp_header(seq: int, ts: int, ssrc: int, pt: int, marker: int = 0) -> bytes:
    b1 = 0x80  # V=2
    b2 = (marker << 7) | (pt & 0x7F)
    return struct.pack("!BBHII", b1, b2, seq & 0xFFFF, ts & 0xFFFFFFFF, ssrc & 0xFFFFFFFF)


def write_wav_header(f, samples: int) -> None:
    datasize = samples * 2
    f.seek(0)
    f.write(b"RIFF")
    f.write(struct.pack("<I", 36 + datasize))
    f.write(b"WAVEfmt ")
    f.write(struct.pack("<IHHIIHH", 16, 1, 1, 8000, 16000, 2, 16))
    f.write(b"data")
    f.write(struct.pack("<I", datasize))


class RtpSession:
    def __init__(
        self,
        local_ip: str,
        rtp_port: int,
        pt: int,
        ssrc: int | None = None,
        symmetric: bool = False,
        save_wav: str | None = None,
        forced: bool = False,
    ) -> None:
        self.local_ip = local_ip
        self.rtp_port = rtp_port
        self.pt = pt
        self.ssrc = ssrc or uuid.uuid4().int & 0xFFFFFFFF
        self.symmetric = symmetric
        self.save_wav = save_wav
        self.port_forced = forced
        self.remote_addr = None
        self.tone_hz = None
        self.send_silence = False
        self.rtcp = False
        self.stats_interval = 2.0
        self.running = False
        self.sent_packets = 0
        self.sent_bytes = 0
        self.recv_packets = 0
        self.recv_bytes = 0
        self.last_seq = None
        self.lost = 0
        self.jitter = 0.0
        self.transit = None
        self.start_time = None
        self.wav_file = None
        self.wav_samples = 0

    def start(self, remote_ip: str | None, remote_port: int | None) -> None:
        base_port = self.rtp_port
        if self.port_forced:
            if base_port % 2 == 1:
                raise ValueError(f"RTP port {base_port} must be even")
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind((self.local_ip, base_port))
            except OSError as e:
                sock.close()
                if e.errno == errno.EADDRINUSE:
                    raise OSError(errno.EADDRINUSE, f"RTP port {base_port} already in use") from e
                raise
            self.rtp_sock = sock
            if self.rtcp:
                rtcp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                rtcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    rtcp_sock.bind((self.local_ip, base_port + 1))
                except OSError as e:
                    rtcp_sock.close()
                    self.rtp_sock.close()
                    if e.errno == errno.EADDRINUSE:
                        raise OSError(
                            errno.EADDRINUSE,
                            f"RTCP port {base_port + 1} already in use",
                        ) from e
                    raise
                self.rtcp_sock = rtcp_sock
        else:
            if base_port % 2 == 1:
                base_port += 1
            selected = None
            for offset in range(0, 22, 2):
                cand = base_port + offset
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    sock.bind((self.local_ip, cand))
                except OSError:
                    sock.close()
                    continue
                rtcp_sock = None
                if self.rtcp:
                    rtcp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    rtcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    try:
                        rtcp_sock.bind((self.local_ip, cand + 1))
                    except OSError:
                        sock.close()
                        rtcp_sock.close()
                        continue
                self.rtp_sock = sock
                if self.rtcp:
                    self.rtcp_sock = rtcp_sock
                self.rtp_port = cand
                selected = cand
                logger.info("RTP port auto-selected %s", cand)
                break
            if selected is None:
                raise OSError("No free RTP port in range")
        self.remote_addr = (
            (remote_ip, remote_port) if remote_ip and remote_port else None
        )
        if self.save_wav:
            self.wav_file = open(self.save_wav, "wb")
            write_wav_header(self.wav_file, 0)
        self.running = True
        self.start_time = time.time()
        self.recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
        self.recv_thread.start()
        if self.tone_hz or self.send_silence:
            self.send_thread = threading.Thread(target=self._send_loop, daemon=True)
            self.send_thread.start()
        if self.stats_interval > 0:
            self.stats_thread = threading.Thread(target=self._stats_loop, daemon=True)
            self.stats_thread.start()

    def set_remote(self, ip: str, port: int) -> None:
        self.remote_addr = (ip, port)

    def stop(self) -> None:
        self.running = False
        try:
            for t in [
                getattr(self, "send_thread", None),
                getattr(self, "recv_thread", None),
                getattr(self, "stats_thread", None),
            ]:
                if t:
                    t.join(timeout=0.2)
        finally:
            for sock in (
                getattr(self, "rtp_sock", None),
                getattr(self, "rtcp_sock", None),
            ):
                if sock:
                    try:
                        sock.close()
                    except OSError:
                        pass
            if self.wav_file:
                try:
                    write_wav_header(self.wav_file, self.wav_samples)
                finally:
                    self.wav_file.close()
                    self.wav_file = None

    def metrics(self) -> dict:
        if not self.start_time:
            return {"pcount": 0, "lost": 0, "jitter": 0.0, "bitrate": 0.0, "pps": 0.0}
        dur = max(time.time() - self.start_time, 1e-6)
        bitrate = (self.recv_bytes * 8) / dur / 1000.0
        pps = self.recv_packets / dur
        return {
            "pcount": self.recv_packets,
            "lost": self.lost,
            "jitter": self.jitter / 8.0,
            "bitrate": bitrate,
            "pps": pps,
        }

    # Internal loops
    def _send_loop(self) -> None:
        seq = 0
        ts = 0
        tone_step = None
        phase = 0.0
        if self.tone_hz:
            tone_step = 2 * math.pi * self.tone_hz / 8000.0
        silence_byte = 0xFF if self.pt == 0 else 0xD5
        while self.running:
            if not self.remote_addr:
                time.sleep(0.02)
                continue
            if self.tone_hz and tone_step:
                samples = [
                    int(32767 * math.sin(phase + i * tone_step)) for i in range(160)
                ]
                phase += 160 * tone_step
                pcm = struct.pack("<160h", *samples)
                payload = (
                    ulaw_encode(pcm) if self.pt == 0 else alaw_encode(pcm)
                )
            elif self.send_silence:
                payload = bytes([silence_byte] * 160)
            else:
                payload = b""
            header = build_rtp_header(seq, ts, self.ssrc, self.pt)
            packet = header + payload
            try:
                self.rtp_sock.sendto(packet, self.remote_addr)
                self.sent_packets += 1
                self.sent_bytes += len(payload)
            except OSError:
                pass
            seq = (seq + 1) & 0xFFFF
            ts = (ts + 160) & 0xFFFFFFFF
            time.sleep(0.02)

    def _recv_loop(self) -> None:
        while self.running:
            try:
                data, addr = self.rtp_sock.recvfrom(2048)
            except OSError:
                break
            if self.symmetric and not self.remote_addr:
                self.remote_addr = addr
            if len(data) < 12:
                continue
            seq = struct.unpack("!H", data[2:4])[0]
            ts = struct.unpack("!I", data[4:8])[0]
            pt = data[1] & 0x7F
            if pt not in (0, 8):
                logger.warning("Unsupported PT=%s", pt)
                continue
            payload = data[12:]
            arrival = time.time()
            self.recv_packets += 1
            self.recv_bytes += len(payload)
            if self.last_seq is not None:
                expected = (self.last_seq + 1) & 0xFFFF
                if seq != expected:
                    diff = (seq - expected) & 0xFFFF
                    if diff > 0:
                        self.lost += diff
            self.last_seq = seq
            transit = arrival * 8000 - ts
            if self.transit is not None:
                d = abs(transit - self.transit)
                self.jitter += (d - self.jitter) / 16.0
            self.transit = transit
            if self.wav_file and payload:
                pcm = (
                    ulaw_decode_to_pcm16(payload)
                    if pt == 0
                    else alaw_decode_to_pcm16(payload)
                )
                try:
                    self.wav_file.write(pcm)
                    self.wav_samples += len(pcm) // 2
                except OSError:
                    pass

    def _stats_loop(self) -> None:
        while self.running:
            time.sleep(self.stats_interval)
            m = self.metrics()
            logger.info(
                "RTP sent=%s recv=%s lost=%s jitter=%.1fms pps=%.1f bitrate=%.1fkbps",
                self.sent_packets,
                m["pcount"],
                m["lost"],
                m["jitter"],
                m["pps"],
                m["bitrate"],
            )
