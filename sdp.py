"""Helpers for SDP generation and parsing supporting PCMU and PCMA."""

from __future__ import annotations

import logging
from typing import Dict, Iterable, List, Tuple

# Mapping between codec names and payload types
PT_FROM_CODEC_NAME = {"pcmu": 0, "pcma": 8, "g729": 18}
CODEC_NAME_FROM_PT = {v: k.upper() for k, v in PT_FROM_CODEC_NAME.items()}


logger = logging.getLogger(__name__)


DIRECTION_SET = {"sendrecv", "sendonly", "recvonly", "inactive"}


def _normalise_direction(direction: str | None) -> str:
    if not direction:
        return "sendrecv"
    value = direction.strip().lower()
    if value not in DIRECTION_SET:
        logger.warning("Invalid SDP direction '%s'; falling back to sendrecv", direction)
        return "sendrecv"
    return value


def parse_direction_from_sdp(sdp_lines: list[str]) -> str:
    """Return negotiated direction from SDP lines following RFC 3264."""

    session_dir: str | None = None
    media_dir: str | None = None
    in_audio = False
    for raw in sdp_lines:
        line = raw.strip()
        if not line:
            continue
        if line.startswith("m="):
            in_audio = line.lower().startswith("m=audio")
            continue
        if not line.startswith("a="):
            continue
        attr = line[2:].strip().lower()
        if attr in DIRECTION_SET:
            if in_audio and media_dir is None:
                media_dir = attr
            elif not in_audio and session_dir is None:
                session_dir = attr
    result = media_dir or session_dir or "sendrecv"
    if result not in DIRECTION_SET:
        return "sendrecv"
    return result


def direction_to_flags(direction: str) -> tuple[bool, bool]:
    """Convert an SDP direction into (send, recv) flags."""

    value = _normalise_direction(direction)
    if value == "sendrecv":
        return True, True
    if value == "sendonly":
        return True, False
    if value == "recvonly":
        return False, True
    return False, False


def flags_to_direction(send: bool, recv: bool) -> str:
    """Return SDP direction string for the given flags."""

    if send and recv:
        return "sendrecv"
    if send and not recv:
        return "sendonly"
    if recv and not send:
        return "recvonly"
    return "inactive"


def offer_allows_for_answer(offer_dir: str) -> tuple[bool, bool]:
    """Return (send, recv) capabilities permitted for an answer."""

    send, recv = direction_to_flags(offer_dir)
    return recv, send


def intersect_answer(offer_dir: str, my_pref_dir: str) -> str:
    """Return answer direction intersecting offer permissions with our prefs."""

    allowed_send, allowed_recv = offer_allows_for_answer(offer_dir)
    want_send, want_recv = direction_to_flags(my_pref_dir)
    return flags_to_direction(allowed_send and want_send, allowed_recv and want_recv)


def _format_codec(pt: int, name: str) -> str:
    codec = name.strip()
    if not codec:
        return str(pt)
    if "/" in codec:
        return codec
    return f"{codec}/8000"


def build_sdp(
    local_ip: str,
    rtp_port: int,
    payloads: Iterable[Tuple[int, str]],
    session_extras: list[str] | None = None,
    media_extras: list[str] | None = None,
    direction: str = "sendrecv",
) -> str:
    """Return SDP string advertising *payloads* and extras."""

    payloads = list(payloads)
    if not payloads:
        raise ValueError("At least one payload type is required for SDP")
    dir_value = _normalise_direction(direction)
    pts = " ".join(str(pt) for pt, _ in payloads)
    lines: list[str] = [
        "v=0",
        f"o=dimitri 0 0 IN IP4 {local_ip}",
        "s=Dimitri-4000",
        f"c=IN IP4 {local_ip}",
        "t=0 0",
    ]
    for extra in session_extras or []:
        extra_line = extra.strip()
        if extra_line:
            lines.append(extra_line)
    media_lines = [f"m=audio {rtp_port} RTP/AVP {pts}"]
    for pt, name in payloads:
        media_lines.append(f"a=rtpmap:{pt} {_format_codec(pt, name)}")
    media_lines.append(f"a={dir_value}")
    for extra in media_extras or []:
        extra_line = extra.strip()
        if extra_line:
            media_lines.append(extra_line)
    all_lines = lines + media_lines
    return "\r\n".join(all_lines) + "\r\n"


def build_sdp_offer(
    ip: str,
    rtp_port: int,
    payloads: Iterable[Tuple[int, str]],
    *,
    session_extras: list[str] | None = None,
    media_extras: list[str] | None = None,
    direction: str = "sendrecv",
) -> str:
    """Wrapper retained for compatibility with previous API."""

    return build_sdp(
        ip,
        rtp_port,
        payloads,
        session_extras=session_extras,
        media_extras=media_extras,
        direction=direction,
    )


def build_sdp_answer(
    ip: str,
    rtp_port: int,
    payloads: Iterable[Tuple[int, str]],
    *,
    session_extras: list[str] | None = None,
    media_extras: list[str] | None = None,
    direction: str = "sendrecv",
) -> str:
    """Wrapper retained for compatibility with previous API."""

    return build_sdp(
        ip,
        rtp_port,
        payloads,
        session_extras=session_extras,
        media_extras=media_extras,
        direction=direction,
    )


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
    lines = text.splitlines()
    for line in lines:
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
    info = {"ip": ip, "audio_port": port, "pts": pts, "rtpmap": rtpmap}
    try:
        info["direction"] = parse_direction_from_sdp(lines)
    except Exception:
        info["direction"] = "sendrecv"
    return info

