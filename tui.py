import curses
import threading
import queue
import time
from collections import deque
from types import SimpleNamespace

from sip_manager import SIPManager
from app import run_load_generator

# Default configuration values for editable fields
DEFAULT_CONFIG = {
    "role": "UAC",
    "bind_ip": "",
    "src_port": "0",
    "rtp_port_base": "40000",
    "dst_host": "127.0.0.1",
    "dst_port": "5060",
    "from_number": "",
    "from_domain": "",
    "from_display": "",
    "to_number": "",
    "to_domain": "",
    "codecs": "pcmu,pcma",
    "rtp_stats_every": "2.0",
    "tone_hz": "",
    "symmetric_rtp": "no",
    "load": "off",
    "calls": "1",
    "rate": "1.0",
    "max_active": "1",
    "to_number_start": "",
    "number_step": "1",
    "pad_width": "0",
    "uas_ring_delay": "1.0",
    "uas_answer_after": "2.0",
    "uas_talk_time": "0.0",
}

FIELD_ORDER = [
    "role",
    "bind_ip",
    "src_port",
    "rtp_port_base",
    "dst_host",
    "dst_port",
    "from_number",
    "from_domain",
    "from_display",
    "to_number",
    "to_domain",
    "codecs",
    "rtp_stats_every",
    "tone_hz",
    "symmetric_rtp",
    "load",
    "calls",
    "rate",
    "max_active",
    "to_number_start",
    "number_step",
    "pad_width",
    "uas_ring_delay",
    "uas_answer_after",
    "uas_talk_time",
]


def run(args):
    """Entry point executed from app.py when --tui flag is present."""
    curses.wrapper(lambda stdscr: TUI(stdscr, args).run())


class TUI:
    def __init__(self, stdscr, args):
        self.stdscr = stdscr
        self.args = args
        self.config = DEFAULT_CONFIG.copy()
        if getattr(args, "dst", None):
            self.config["dst_host"] = args.dst
        if getattr(args, "dst_port", None):
            self.config["dst_port"] = str(args.dst_port)
        self.selected = 0
        self.log = deque(maxlen=50)
        self.state = {
            "options": {"sent": 0, "ok": 0, "other": 0, "timeout": 0},
            "uac": {
                "launched": 0,
                "active": 0,
                "established": 0,
                "failed_4xx": 0,
                "failed_5xx": 0,
                "canceled": 0,
                "remote_bye": 0,
            },
            "uas": {"dialogs": 0},
        }
        self.cmd_q: queue.Queue = queue.Queue()
        self.event_q: queue.Queue = queue.Queue()
        self.stop_event = threading.Event()
        self.controller = threading.Thread(
            target=controller,
            args=(self.cmd_q, self.event_q, self.stop_event),
            daemon=True,
        )
        self.controller.start()

    # ------------------------------------------------------------------
    def run(self):
        curses.curs_set(0)
        self.stdscr.nodelay(True)
        while not self.stop_event.is_set():
            self._process_events()
            self._draw()
            c = self.stdscr.getch()
            if c == curses.KEY_UP:
                self.selected = (self.selected - 1) % len(FIELD_ORDER)
            elif c == curses.KEY_DOWN:
                self.selected = (self.selected + 1) % len(FIELD_ORDER)
            elif c in (curses.KEY_ENTER, 10, 13):
                self._edit_field()
            elif c == curses.KEY_F5:
                self.cmd_q.put(("options", self.config.copy()))
            elif c == curses.KEY_F6:
                self.cmd_q.put(("start_uas", self.config.copy()))
            elif c == curses.KEY_F7:
                self.cmd_q.put(("call", self.config.copy()))
            elif c == curses.KEY_F8:
                self.cmd_q.put(("load", self.config.copy()))
            elif c == curses.KEY_F9:
                self.cmd_q.put(("stop", None))
            elif c in (27, 3):  # ESC or Ctrl+C
                self.cmd_q.put(("stop", None))
                break
            time.sleep(0.05)
        self.stop_event.set()
        self.controller.join()

    # ------------------------------------------------------------------
    def _process_events(self):
        while True:
            try:
                kind, data = self.event_q.get_nowait()
            except queue.Empty:
                break
            if kind == "log":
                self.log.append(data)
            elif kind == "options":
                self.state["options"].update(data)
            elif kind == "uac":
                self.state["uac"].update(data)
            elif kind == "uas":
                self.state["uas"].update(data)

    # ------------------------------------------------------------------
    def _draw(self):
        self.stdscr.erase()
        self.stdscr.addstr(0, 0, "Dimitri 4000 TUI - F5 OPTIONS F6 UAS F7 CALL F8 LOAD F9 STOP ESC quit")
        for idx, key in enumerate(FIELD_ORDER):
            val = self.config.get(key, "")
            line = f"{key}: {val}"
            if idx == self.selected:
                self.stdscr.attron(curses.A_REVERSE)
                self.stdscr.addstr(2 + idx, 0, line)
                self.stdscr.attroff(curses.A_REVERSE)
            else:
                self.stdscr.addstr(2 + idx, 0, line)
        base = 2 + len(FIELD_ORDER) + 1
        opt = self.state["options"]
        uac = self.state["uac"]
        uas = self.state["uas"]
        self.stdscr.addstr(base, 0, "Estado:")
        self.stdscr.addstr(
            base + 1,
            0,
            f"OPTIONS sent={opt['sent']} 200={opt['ok']} other={opt['other']} timeout={opt['timeout']}",
        )
        self.stdscr.addstr(
            base + 2,
            0,
            (
                f"UAC launched={uac['launched']} active={uac['active']} established={uac['established']} "
                f"4xx={uac['failed_4xx']} 5xx={uac['failed_5xx']} canceled={uac['canceled']} "
                f"remote_bye={uac['remote_bye']}"
            ),
        )
        self.stdscr.addstr(base + 3, 0, f"UAS dialogs={uas['dialogs']}")
        self.stdscr.addstr(base + 5, 0, "Log:")
        for i, line in enumerate(list(self.log)[-5:]):
            self.stdscr.addstr(base + 6 + i, 0, line)
        self.stdscr.refresh()

    # ------------------------------------------------------------------
    def _edit_field(self):
        key = FIELD_ORDER[self.selected]
        val = self.config.get(key, "")
        self.stdscr.addstr(2 + self.selected, 0, f"{key}: ")
        self.stdscr.clrtoeol()
        curses.echo()
        new_val = self.stdscr.getstr(2 + self.selected, len(key) + 2).decode().strip()
        curses.noecho()
        if new_val:
            self.config[key] = new_val
        else:
            self.config[key] = ""


# ----------------------------------------------------------------------
# Controller and worker threads
# ----------------------------------------------------------------------

def controller(cmd_q, event_q, stop_event):
    workers = {}
    while not stop_event.is_set():
        try:
            cmd, cfg = cmd_q.get(timeout=0.1)
        except queue.Empty:
            continue
        if cmd == "options":
            t = threading.Thread(target=options_worker, args=(cfg, event_q))
            t.start()
        elif cmd == "call":
            t = threading.Thread(target=call_worker, args=(cfg, event_q))
            t.start()
        elif cmd == "load":
            if workers.get("load") and workers["load"].is_alive():
                continue
            t = threading.Thread(target=load_worker, args=(cfg, event_q, stop_event))
            t.start()
            workers["load"] = t
        elif cmd == "start_uas":
            if workers.get("uas") and workers["uas"].is_alive():
                continue
            t = threading.Thread(target=uas_worker, args=(cfg, event_q, stop_event))
            t.start()
            workers["uas"] = t
        elif cmd == "stop":
            stop_event.set()
            break
    for w in workers.values():
        w.join(timeout=1)
    event_q.put(("log", "Stopped"))


# ----------------------------------------------------------------------
# Worker helpers
# ----------------------------------------------------------------------

def options_worker(cfg, event_q):
    counters = {"sent": 0, "ok": 0, "other": 0, "timeout": 0}
    sm = SIPManager(protocol="udp")
    dst = cfg.get("dst_host")
    dport = int(cfg.get("dst_port", 5060))
    for _ in range(3):
        counters["sent"] += 1
        try:
            code, reason, _ = sm.send_request(dst_host=dst, dst_port=dport)
        except OSError as exc:
            event_q.put(("log", f"OPTIONS error: {exc}"))
            counters["other"] += 1
        else:
            if code is None:
                counters["timeout"] += 1
            elif code == 200:
                counters["ok"] += 1
            else:
                counters["other"] += 1
        event_q.put(("options", counters.copy()))
        time.sleep(0.5)
    event_q.put(("log", "OPTIONS test finished"))


def call_worker(cfg, event_q):
    counters = {
        "launched": 1,
        "active": 1,
        "established": 0,
        "failed_4xx": 0,
        "failed_5xx": 0,
        "canceled": 0,
        "remote_bye": 0,
    }
    event_q.put(("uac", counters.copy()))
    sm = SIPManager(protocol="udp")
    dst = cfg.get("dst_host")
    dport = int(cfg.get("dst_port", 5060))
    try:
        _, result, _, _ = sm.place_call(
            dst_host=dst,
            dst_port=dport,
            from_number=cfg.get("from_number") or "1000",
            from_domain=cfg.get("from_domain") or None,
            from_display=cfg.get("from_display") or None,
            to_number=cfg.get("to_number") or "1001",
            to_domain=cfg.get("to_domain") or None,
            codecs=[(0, "PCMU"), (8, "PCMA")],
            rtp_port=int(cfg.get("rtp_port_base", "40000")),
            rtp_port_forced=True,
            stats_interval=float(cfg.get("rtp_stats_every", "2.0")),
        )
    except Exception as exc:  # noqa: BLE001
        event_q.put(("log", f"Call error: {exc}"))
        result = "error"
    if result in ("answered", "remote-bye", "max-time-bye"):
        counters["established"] += 1
    if result.startswith("rejected(4") or result.startswith("busy"):
        counters["failed_4xx"] += 1
    if result.startswith("rejected(5") or result.startswith("rejected(6"):
        counters["failed_5xx"] += 1
    if result.startswith("canceled"):
        counters["canceled"] += 1
    if result == "remote-bye":
        counters["remote_bye"] += 1
    counters["active"] = 0
    event_q.put(("uac", counters.copy()))
    event_q.put(("log", f"Call result: {result}"))


def load_worker(cfg, event_q, stop_event):
    args = SimpleNamespace(
        dst=cfg.get("dst_host"),
        dst_port=int(cfg.get("dst_port", 5060)),
        host=None,
        port=None,
        to_uri_pattern=None,
        to_number_start=cfg.get("to_number_start") or "1000",
        from_number_start=cfg.get("from_number") or "1000",
        number_step=int(cfg.get("number_step", "1")),
        pad_width=int(cfg.get("pad_width", "0")),
        from_number=None,
        from_user="dimitri",
        to_domain_load=cfg.get("to_domain") or cfg.get("dst_host"),
        from_domain_load=cfg.get("from_domain") or (cfg.get("bind_ip") or ""),
        src_port_base=int(cfg.get("src_port", "0")),
        src_port_step=10,
        rtp_port_base=int(cfg.get("rtp_port_base", "40000")),
        rtp_port_step=2,
        bind_ip=cfg.get("bind_ip") or None,
        timeout=2.0,
        ring_timeout=15.0,
        talk_time=float(cfg.get("uas_talk_time", "0")),
        wait_bye=False,
        max_call_time=0.0,
        codecs=[(0, "PCMU")],
        rtcp=False,
        rtp_tone=None,
        rtp_send_silence=False,
        symmetric_rtp=False,
        rtp_stats_every=float(cfg.get("rtp_stats_every", "2.0")),
        calls=int(cfg.get("calls", "1")),
        rate=float(cfg.get("rate", "1.0")),
        max_active=int(cfg.get("max_active", "1")),
    )
    sm = SIPManager(protocol="udp")

    def stats_cb(snapshot):
        event_q.put(("uac", snapshot))

    run_load_generator(args, sm, stats_cb=stats_cb)
    event_q.put(("log", "Load finished"))


def uas_worker(cfg, event_q, stop_event):
    event_q.put(("log", "UAS service started"))
    try:
        while not stop_event.is_set():
            time.sleep(0.5)
    finally:
        event_q.put(("log", "UAS service stopped"))

