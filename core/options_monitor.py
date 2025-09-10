import logging
import time
from typing import Dict, Tuple

from .reactor import Reactor
from sip_manager import build_options, parse_headers, status_from_response, build_response

logger = logging.getLogger(__name__)


class OptionsMonitor:
    """Send periodic SIP OPTIONS using a shared :class:`Reactor`.

    Counters are exposed via attributes ``sent``, ``ok200``, ``other`` and
    ``timeouts``. ``last_status`` stores the last result as string.
    """

    def __init__(
        self,
        reac: Reactor,
        *,
        dst_host: str,
        dst_port: int,
        interval: float = 1.0,
        timeout: float = 2.0,
        cseq_start: int = 1,
        name: str = "options",
    ) -> None:
        self.reac = reac
        self.dst_host = dst_host
        self.dst_port = dst_port
        self.interval = interval
        self.timeout = timeout
        self.cseq = cseq_start
        self.name = name

        self.sent = 0
        self.ok200 = 0
        self.other = 0
        self.timeouts = 0
        self.last_status = ""

        self._reader_token: int | None = None
        self._periodic_token: int | None = None
        self._pending: Dict[Tuple[str, int], int] = {}

    # ------------------------------------------------------------------
    def start(self) -> None:
        if self._reader_token is not None:
            return
        self._reader_token = self.reac.add_reader(self._on_datagram)
        self._periodic_token = self.reac.add_periodic(self.interval, self._on_tick)
        logger.info("[options] monitor started → %s:%s", self.dst_host, self.dst_port)

    def stop(self) -> None:
        if self._reader_token is not None:
            self.reac.cancel(self._reader_token)
            self._reader_token = None
        if self._periodic_token is not None:
            self.reac.cancel(self._periodic_token)
            self._periodic_token = None
        for token in list(self._pending.values()):
            self.reac.cancel(token)
        self._pending.clear()
        logger.info("[options] monitor stopped")

    def reset(self) -> None:
        self.sent = self.ok200 = self.other = self.timeouts = 0
        self.last_status = ""

    # ------------------------------------------------------------------
    def _on_tick(self) -> None:
        call_id, payload = build_options(
            self.dst_host,
            self.reac.local_ip,
            self.reac.local_port,
            self.name,
            self.cseq,
        )
        self.reac.sendto(payload, (self.dst_host, self.dst_port))
        self.sent += 1
        key = (call_id, self.cseq)
        token = self.reac.add_timer(time.monotonic() + self.timeout, lambda: self._on_timeout(key))
        self._pending[key] = token
        logger.info("[options] sent CSeq=%s to %s:%s", self.cseq, self.dst_host, self.dst_port)
        self.cseq += 1

    def _on_datagram(self, data: bytes, addr: Tuple[str, int]) -> None:
        if addr[0] != self.dst_host or addr[1] != self.dst_port:
            return
        text = data.decode(errors="ignore")
        if not text.startswith("SIP/2.0"):
            return
        start, headers = parse_headers(data)
        call_id = headers.get("call-id")
        cseq_header = headers.get("cseq", "0")
        try:
            cseq = int(cseq_header.split()[0])
        except ValueError:
            return
        key = (call_id, cseq)
        timer = self._pending.pop(key, None)
        if timer is None:
            return
        self.reac.cancel(timer)
        code, reason = status_from_response(data)
        if code == 200:
            self.ok200 += 1
        else:
            self.other += 1
        self.last_status = f"{code} {reason}"
        logger.info("[options] reply CSeq=%s → %s", cseq, self.last_status)

    def _on_timeout(self, key: Tuple[str, int]) -> None:
        if key in self._pending:
            del self._pending[key]
            self.timeouts += 1
            self.last_status = "timeout"
            logger.info("[options] timeout CSeq=%s", key[1])


def register_options_responder(reac: Reactor) -> int:
    """Register a simple responder for incoming OPTIONS requests."""

    def _cb(data: bytes, addr: Tuple[str, int]) -> None:
        text = data.decode(errors="ignore")
        if not text.startswith("OPTIONS"):
            return
        start, headers = parse_headers(data)
        via = headers.get("via", "")
        to = headers.get("from", "")
        frm = headers.get("to", "")
        headers_resp = {"Via": via, "To": frm, "From": to}
        resp = build_response(200, "OK", headers_resp)
        reac.sendto(resp, addr)
        logger.info("[options] replied 200 to %s:%s", addr[0], addr[1])

    return reac.add_reader(_cb)
