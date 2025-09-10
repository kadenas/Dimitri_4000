import re

_C_LINE = re.compile(rb"^c=IN IP4 ([0-9\.]+)\s*$", re.MULTILINE)
_M_AUDIO = re.compile(rb"^m=audio (\d+) RTP/AVP ([0-9 ]+)\s*$", re.MULTILINE)

def parse_sdp_ip_port(sdp_bytes: bytes):
    """Devuelve (ip, port) del SDP (c= y m=audio). Lanza ValueError si falta."""
    m_ip = _C_LINE.search(sdp_bytes)
    m_ma = _M_AUDIO.search(sdp_bytes)
    if not (m_ip and m_ma):
        raise ValueError("SDP sin c= o m=audio")
    ip = m_ip.group(1).decode()
    port = int(m_ma.group(1).decode())
    return ip, port
