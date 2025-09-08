'''Helpers for SDP generation and parsing supporting PCMU and PCMA.'''

from __future__ import annotations

from typing import Dict, List

# Mapping between codec names and payload types
PT_FROM_CODEC_NAME = {"pcmu": 0, "pcma": 8}
CODEC_NAME_FROM_PT = {v: k.upper() for k, v in PT_FROM_CODEC_NAME.items()}


def build_sdp(local_ip: str, rtp_port: int, pts: List[int]) -> bytes:
    """Return minimal SDP offer/answer advertising the given payload types."""
    pt_list = " ".join(str(pt) for pt in pts)
    lines = [
        "v=0\r\n",
        f"o=dimitri 0 0 IN IP4 {local_ip}\r\n",
        "s=Dimitri-4000\r\n",
        f"c=IN IP4 {local_ip}\r\n",
        "t=0 0\r\n",
        f"m=audio {rtp_port} RTP/AVP {pt_list}\r\n",
    ]
    for pt in pts:
        codec = CODEC_NAME_FROM_PT.get(pt, str(pt))
        lines.append(f"a=rtpmap:{pt} {codec}/8000\r\n")
    lines.append("a=sendrecv\r\n")
    return "".join(lines).encode()


def parse_sdp(body: bytes | str) -> Dict:
    """Parse minimal SDP returning connection info and codec mappings."""
    if isinstance(body, bytes):
        text = body.decode(errors="ignore")
    else:
        text = body
    ip = None
    port = None
    pts: List[int] = []
    rtpmap: Dict[int, str] = {}
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
                    pts = [int(p) for p in parts[3:] if p.isdigit()]
                except ValueError:
                    pass
        elif line.startswith("a=rtpmap:"):
            try:
                p = line.split(None, 1)[0]
                pt = int(p.split(":", 1)[1])
                codec = line.split(None, 1)[1].split("/", 1)[0].upper()
                rtpmap[pt] = codec
            except Exception:
                continue
    return {"ip": ip, "audio_port": port, "pts": pts, "rtpmap": rtpmap}

