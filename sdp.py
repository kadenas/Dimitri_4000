"""Helpers for SDP generation and parsing."""


def build_sdp(local_ip: str, rtp_port: int, pt: int) -> str:
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
    ip = port = pt = None
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

