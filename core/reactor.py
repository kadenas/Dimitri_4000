import socket
import select
import heapq
import time
import threading
from typing import Callable, Dict, List, Tuple, Any


class Reactor:
    """Simple select()-based reactor for a single UDP socket.

    It multiplexes incoming datagrams and timers. Readers receive each
    datagram as ``callback(data, addr)``. Timers are managed via ``heapq`` and
    can be one-shot or periodic.
    """

    def __init__(self, bind_ip: str, src_port: int, *, recv_buf: int = 8192) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((bind_ip, src_port))
        self.local_ip, self.local_port = self.sock.getsockname()
        self._recv_buf = recv_buf

        self._readers: Dict[int, Callable[[bytes, Tuple[str, int]], None]] = {}
        self._next_token = 1

        self._timers: List[Tuple[float, int, Callable[[], None], List[bool]]] = []
        self._timers_lookup: Dict[int, List[bool]] = {}

        self._send_lock = threading.Lock()
        self._running = False

    # Reader management -------------------------------------------------
    def add_reader(self, cb: Callable[[bytes, Tuple[str, int]], None]) -> int:
        token = self._next_token
        self._next_token += 1
        self._readers[token] = cb
        return token

    def remove_reader(self, token: int) -> None:
        self._readers.pop(token, None)

    # Timer management --------------------------------------------------
    def add_timer(self, when_monotonic: float, cb: Callable[[], None]) -> int:
        token = self._next_token
        self._next_token += 1
        active = [True]
        entry = (when_monotonic, token, cb, active)
        heapq.heappush(self._timers, entry)
        self._timers_lookup[token] = active
        return token

    def add_periodic(self, interval_s: float, cb: Callable[[], None]) -> int:
        token = self._next_token
        self._next_token += 1
        active = [True]

        def _wrap() -> None:
            if not active[0]:
                return
            cb()
            next_when = time.monotonic() + interval_s
            heapq.heappush(self._timers, (next_when, token, _wrap, active))

        next_when = time.monotonic() + interval_s
        heapq.heappush(self._timers, (next_when, token, _wrap, active))
        self._timers_lookup[token] = active
        return token

    def cancel(self, token: int) -> None:
        active = self._timers_lookup.pop(token, None)
        if active:
            active[0] = False
        self._readers.pop(token, None)

    # Sending -----------------------------------------------------------
    def sendto(self, data: bytes, addr: Tuple[str, int]) -> None:
        with self._send_lock:
            self.sock.sendto(data, addr)

    # Loop --------------------------------------------------------------
    def run(self) -> None:
        self._running = True
        try:
            while self._running:
                timeout = None
                now = time.monotonic()
                if self._timers:
                    when, _, _, _ = self._timers[0]
                    timeout = max(0, when - now)
                rlist, _, _ = select.select([self.sock], [], [], timeout)
                if rlist:
                    data, addr = self.sock.recvfrom(self._recv_buf)
                    for cb in list(self._readers.values()):
                        try:
                            cb(data, addr)
                        except Exception:
                            pass
                now = time.monotonic()
                while self._timers and self._timers[0][0] <= now:
                    _, token, cb, active = heapq.heappop(self._timers)
                    if active[0]:
                        try:
                            cb()
                        except Exception:
                            pass
                        if token not in self._timers_lookup:
                            # one-shot timer removed earlier
                            continue
                # cleanup cancelled timers from heap
                self._timers = [t for t in self._timers if t[3][0]]
                heapq.heapify(self._timers)
        finally:
            self.sock.close()
            self._timers.clear()
            self._timers_lookup.clear()
            self._readers.clear()

    def stop(self) -> None:
        self._running = False
        try:
            self.sock.close()
        except OSError:
            pass

