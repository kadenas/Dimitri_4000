"""Helpers for SDP generation."""

def build_sdp(local_ip: str, rtp_port: int, codec: str) -> str:
    """Return a minimal SDP offer for a single audio stream."""
    codec = codec.lower()
    if codec not in {"pcmu", "pcma"}:
        codec = "pcmu"
    pt = 0 if codec == "pcmu" else 8
    sdp = (
        "v=0\r\n"
        f"o=dimitri 0 0 IN IP4 {local_ip}\r\n"
        "s=Dimitri-4000\r\n"
        f"c=IN IP4 {local_ip}\r\n"
        "t=0 0\r\n"
        f"m=audio {rtp_port} RTP/AVP {pt}\r\n"
        f"a=rtpmap:{pt} {codec.upper()}/8000\r\n"
    )
    return sdp

