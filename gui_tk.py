import os
import json
import logging
import threading
import queue
import time
import socket
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from types import SimpleNamespace
import uuid

from sdp import build_sdp, parse_sdp, PT_FROM_CODEC_NAME, build_sdp_offer
from sdp_utils import parse_sdp_ip_port
from rtp import RtpSession

from sip_manager import (
    SIPManager,
    build_response,
    parse_headers,
    build_options,
    build_cancel,
    build_trying,
    build_ringing,
    build_200,
    build_487,
)
from app import run_load_generator

# Configuration persisted in user home directory
CONFIG_PATH = os.path.expanduser("~/.dimitri4000.json")

DEFAULT_CONFIG = {
    "bind_ip": "",
    "src_port": "0",
    "use_src_port_options": True,
    "interval": "1.0",
    "timeout": "2.0",
    "cseq_start": "1",
    "reply_options": False,
    "dst_host": "127.0.0.1",
    "dst_port": "5060",
    "codecs": "pcmu,pcma",
    "rtp_port_base": "40000",
    "symmetric_rtp": False,
    "rtp_stats_every": "2.0",
    "tone_hz": "0",
    "send_silence": False,
    "role": "UAC",
    "from_number": "",
    "from_domain": "",
    "from_display": "",
    "to_number": "",
    "to_domain": "",
    "from_uri": "",
    "to_uri": "",
    "auth_user": "",
    "auth_pass": "",
    "use_auth": False,
    "wait_bye": True,
    "require_health_call": True,
    # load
    "load": False,
    "calls": "1",
    "rate": "1.0",
    "max_active": "1",
    "from_number_start": "",
    "to_number_start": "",
    "number_step": "1",
    "pad_width": "0",
    "src_port_base": "0",
    "src_port_step": "10",
    "rtp_port_step": "2",
    "ignore_health": False,
}


def load_config():
    try:
        with open(CONFIG_PATH, "r", encoding="utf8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_config(cfg):
    try:
        with open(CONFIG_PATH, "w", encoding="utf8") as f:
            json.dump(cfg, f, indent=2)
    except Exception:
        pass


class LogHandler(logging.Handler):
    def __init__(self, q):
        super().__init__()
        self.q = q

    def emit(self, record):
        self.q.put(("log", self.format(record)))


class App(tk.Tk):
    def __init__(self, args=None):
        super().__init__()
        self.title("Dimitri 4000 GUI")
        self.event_q: queue.Queue = queue.Queue()
        self.stop_event = threading.Event()
        self.state = {
            "options": {
                "sent": 0,
                "ok200": 0,
                "other": 0,
                "timeouts": 0,
                "last": "-",
                "rx": 0,
            },
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
        self.health_state = "FAIL"     # "OK" | "FAIL"
        self.last_200_ts = 0.0
        self.health_grace_s = 5.0      # ventana de gracia desde el último 200
        self.fail_streak = 0
        self.fail_threshold = 3        # nº de fallos seguidos para marcar FAIL si no hay 200 reciente
        cfg = DEFAULT_CONFIG.copy()
        cfg.update(load_config())
        self.vars: dict[str, tk.Variable] = {}
        self.widgets: dict[str, ttk.Entry] = {}
        # shared SIP manager so dialogs can be controlled from GUI
        self.sm = SIPManager(protocol="udp")
        self.load_thread = None
        self.uas_thread = None
        self._build_ui(cfg)
        self.log_handler = LogHandler(self.event_q)
        logging.getLogger().addHandler(self.log_handler)
        self.after(200, self._process_events)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Status.OK.TLabel", background="#c6f6d5")
        style.configure("Status.Bad.TLabel", background="#fed7d7")
        style.configure("Status.Warn.TLabel", background="#f7e7a5")

    # ------------------------------------------------------------------
    def _build_ui(self, cfg):
        self.setup_styles()

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True)

        # ------------------ General tab ------------------
        general = ttk.Frame(nb)
        nb.add(general, text="General")

        lf_origen = ttk.LabelFrame(general, text="Origen")
        lf_origen.grid(row=0, column=0, sticky="nsew", padx=8, pady=4)
        self._add_entry(lf_origen, "bind_ip", 0, cfg)
        self._add_entry(lf_origen, "src_port", 1, cfg)

        lf_dest = ttk.LabelFrame(general, text="Destino")
        lf_dest.grid(row=1, column=0, sticky="nsew", padx=8, pady=4)
        self._add_entry(lf_dest, "dst_host", 0, cfg)
        self.entry_dst_host = self.widgets["dst_host"]
        self._add_entry(lf_dest, "dst_port", 1, cfg)
        self.entry_dst_port = self.widgets["dst_port"]

        lf_audio = ttk.LabelFrame(general, text="Audio")
        lf_audio.grid(row=2, column=0, sticky="nsew", padx=8, pady=4)
        self._add_entry(lf_audio, "codecs", 0, cfg)
        self._add_entry(lf_audio, "rtp_port_base", 1, cfg)
        self._add_check(lf_audio, "symmetric_rtp", 2, cfg, text="symmetric_rtp")
        self._add_entry(lf_audio, "rtp_stats_every", 3, cfg)
        self._add_entry(lf_audio, "tone_hz", 4, cfg)
        self._add_check(lf_audio, "send_silence", 5, cfg, text="send_silence")

        lf_mode = ttk.LabelFrame(general, text="Modo")
        lf_mode.grid(row=3, column=0, sticky="nsew", padx=8, pady=4)
        self.vars["role"] = tk.StringVar(value=cfg.get("role", "UAC"))
        self.role_var = self.vars["role"]
        ttk.Radiobutton(
            lf_mode,
            text="UAC",
            variable=self.vars["role"],
            value="UAC",
            command=self._refresh_buttons_state,
        ).grid(row=0, column=0, sticky="w")
        ttk.Radiobutton(
            lf_mode,
            text="UAS",
            variable=self.vars["role"],
            value="UAS",
            command=self._refresh_buttons_state,
        ).grid(row=0, column=1, sticky="w")
        self._add_check(lf_mode, "wait_bye", 1, cfg, text="esperar BYE")
        self._add_check(
            lf_mode,
            "require_health_call",
            2,
            cfg,
            text="exigir health para llamadas",
        )

        lf_opts = ttk.LabelFrame(general, text="Monitorización OPTIONS")
        lf_opts.grid(row=4, column=0, sticky="nsew", padx=8, pady=4)
        self._add_entry(lf_opts, "interval", 0, cfg)
        self._add_entry(lf_opts, "timeout", 1, cfg)
        self._add_entry(lf_opts, "cseq_start", 2, cfg)
        self._add_check(
            lf_opts,
            "use_src_port_options",
            3,
            cfg,
            text="usar src_port para OPTIONS",
        )
        self._add_check(lf_opts, "reply_options", 4, cfg, text="Responder OPTIONS")

        opt_btns = ttk.Frame(lf_opts)
        opt_btns.grid(row=5, column=0, columnspan=2, pady=4)
        self.mon_start_btn = ttk.Button(
            opt_btns, text="Iniciar monitor", command=self.start_options_monitor
        )
        self.mon_stop_btn = ttk.Button(
            opt_btns, text="Parar monitor", command=self.stop_options_monitor
        )
        self.mon_reset_btn = ttk.Button(
            opt_btns, text="Reset", command=self.reset_options_monitor
        )
        self.mon_copy_btn = ttk.Button(
            opt_btns, text="Copiar comando CLI", command=self.copy_cli_command
        )
        for i, b in enumerate(
            [self.mon_start_btn, self.mon_stop_btn, self.mon_reset_btn, self.mon_copy_btn]
        ):
            b.grid(row=0, column=i, padx=2)

        self.monitor_status_lbl = ttk.Label(
            lf_opts, text="monitor: PARADO", style="Status.Warn.TLabel"
        )
        self.monitor_status_lbl.grid(
            row=6, column=0, columnspan=2, sticky="w", padx=8, pady=2
        )
        self.monitor_counts_lbl = ttk.Label(
            lf_opts,
            text="sent=0 200=0 other=0 timeout=0 last=-",
            style="Status.Warn.TLabel",
        )
        self.monitor_counts_lbl.grid(
            row=7, column=0, columnspan=2, sticky="w", padx=8, pady=2
        )
        self.monitor_rx_lbl = ttk.Label(lf_opts, text="rx_options=0")
        self.monitor_rx_lbl.grid(row=8, column=0, columnspan=2, sticky="w", padx=8)

        # ------------------ Identity tab ------------------
        identity = ttk.Frame(nb)
        nb.add(identity, text="Identidad y SIP")

        lf_ft = ttk.LabelFrame(identity, text="From/To y URIs (opcional)")
        lf_ft.grid(row=0, column=0, sticky="nsew", padx=8, pady=4)
        self._add_entry(lf_ft, "from_number", 0, cfg)
        self._add_entry(lf_ft, "from_domain", 1, cfg)
        self._add_entry(lf_ft, "from_display", 2, cfg)
        self._add_entry(lf_ft, "to_number", 3, cfg)
        self._add_entry(lf_ft, "to_domain", 4, cfg)
        self._add_entry(lf_ft, "from_uri", 5, cfg)
        self._add_entry(lf_ft, "to_uri", 6, cfg)

        lf_auth = ttk.LabelFrame(identity, text="Auth (opcional)")
        lf_auth.grid(row=1, column=0, sticky="nsew", padx=8, pady=4)
        self._add_check(lf_auth, "use_auth", 0, cfg, text="usar auth")
        self._add_entry(lf_auth, "auth_user", 1, cfg)
        self._add_entry(lf_auth, "auth_pass", 2, cfg, show="*")

        cfg["src_port_step"] = cfg.get("src_port_step") or "10"
        cfg["rtp_port_step"] = cfg.get("rtp_port_step") or "2"

        # ------------------ Load tab ------------------
        load = ttk.Frame(nb)
        nb.add(load, text="Carga")

        lf_load = ttk.LabelFrame(load, text="Parámetros de carga")
        lf_load.grid(row=0, column=0, sticky="nsew", padx=8, pady=4)
        self._add_check(lf_load, "load", 0, cfg, text="load")
        self._add_entry(lf_load, "calls", 1, cfg)
        self.entry_calls = self.widgets["calls"]
        self._add_entry(lf_load, "rate", 2, cfg)
        self.entry_rate = self.widgets["rate"]
        self._add_entry(lf_load, "max_active", 3, cfg)
        self.entry_max_active = self.widgets["max_active"]
        self._add_entry(lf_load, "from_number_start", 4, cfg)
        self.entry_from_start = self.widgets["from_number_start"]
        self._add_entry(lf_load, "to_number_start", 5, cfg)
        self.entry_to_start = self.widgets["to_number_start"]
        self._add_entry(lf_load, "number_step", 6, cfg)
        self.entry_number_step = self.widgets["number_step"]
        self._add_entry(lf_load, "pad_width", 7, cfg)
        self.entry_pad_width = self.widgets["pad_width"]
        self._add_entry(lf_load, "src_port_base", 8, cfg)
        self.entry_src_port_base = self.widgets["src_port_base"]
        self._add_entry(lf_load, "src_port_step", 9, cfg)
        self.entry_src_port_step = self.widgets["src_port_step"]
        self._add_entry(lf_load, "rtp_port_step", 10, cfg)
        self.entry_rtp_port_step = self.widgets["rtp_port_step"]
        self._add_check(lf_load, "ignore_health", 11, cfg, text="ignorar health")
        self.load_tab_btn = ttk.Button(load, text="Iniciar Generador", command=self.start_load)
        self.load_tab_btn.grid(row=1, column=0, pady=8)

        # separator and main button row
        ttk.Separator(self, orient="horizontal").pack(fill="x", pady=4)
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill="x")
        self.opt_btn = ttk.Button(btn_frame, text="Probar OPTIONS", command=self.start_options)
        self.uas_btn = ttk.Button(btn_frame, text="Iniciar UAS", command=self.toggle_uas)
        self.call_btn = ttk.Button(btn_frame, text="Llamada UAC", command=self.on_uac_call_clicked)
        self.load_btn = ttk.Button(btn_frame, text="Generador", command=self.start_load)
        self.bye_uac_btn = ttk.Button(btn_frame, text="BYE todas (UAC)", command=self.on_bye_all_uac)
        self.bye_uas_btn = ttk.Button(btn_frame, text="BYE todas (UAS)", command=self.on_bye_all_uas)
        self.stop_btn = ttk.Button(btn_frame, text="Detener todo", command=self.stop_all)
        for i, b in enumerate([self.opt_btn, self.uas_btn, self.call_btn, self.load_btn, self.bye_uac_btn, self.bye_uas_btn, self.stop_btn]):
            b.grid(row=0, column=i, padx=2, pady=2)

        # Status / log
        status = ttk.Frame(self)
        status.pack(fill="both", expand=True)
        self.health_lbl = ttk.Label(
            status, text="health: FAIL", style="Status.Bad.TLabel"
        )
        self.health_lbl.pack(anchor="w")
        self.uas_status_lbl = ttk.Label(status, text="UAS: PARADO", style="Status.Warn.TLabel")
        self.uas_status_lbl.pack(anchor="w")
        self.gen_status_lbl = ttk.Label(status, text="Generador: PARADO", style="Status.Warn.TLabel")
        self.gen_status_lbl.pack(anchor="w")
        self.uac_lbl = ttk.Label(status, text="UAC: -")
        self.uac_lbl.pack(anchor="w")
        self.uas_lbl = ttk.Label(status, text="UAS dialogs=0")
        self.uas_lbl.pack(anchor="w")
        log_frame = ttk.Frame(status)
        log_frame.pack(fill="both", expand=True)
        self.log_text = tk.Text(log_frame, height=10)
        self.log_text.pack(side="left", fill="both", expand=True)
        scroll = ttk.Scrollbar(log_frame, command=self.log_text.yview)
        scroll.pack(side="right", fill="y")
        self.log_text['yscrollcommand'] = scroll.set
        ttk.Button(status, text="Guardar log...", command=self.save_log).pack(anchor="e")
        self._refresh_buttons_state()
        for key in ("bind_ip", "dst_host", "src_port", "dst_port", "calls", "role"):
            if key in self.vars:
                self.vars[key].trace_add("write", lambda *a: self._refresh_buttons_state())
        for w in [
            self.entry_calls,
            self.entry_dst_host,
            self.entry_dst_port,
            self.entry_src_port_base,
            self.entry_src_port_step,
            self.entry_rtp_port_step,
        ]:
            w.bind("<KeyRelease>", lambda e: self._refresh_buttons_state())
            w.bind("<FocusOut>", lambda e: self._refresh_buttons_state())

    # helpers -----------------------------------------------------------
    def _add_entry(self, parent, key, row, cfg, show=None):
        ttk.Label(parent, text=key).grid(row=row, column=0, sticky="w", padx=8, pady=4)
        var = tk.StringVar(value=cfg.get(key, ""))
        e = ttk.Entry(parent, textvariable=var, show=show)
        e.grid(row=row, column=1, sticky="ew", padx=8, pady=4)
        parent.grid_columnconfigure(1, weight=1)
        self.vars[key] = var
        self.widgets[key] = e

    def _add_check(self, parent, key, row, cfg, text=None):
        var = tk.BooleanVar(value=cfg.get(key, False))
        chk = ttk.Checkbutton(
            parent, text=text or key, variable=var, command=self._refresh_buttons_state
        )
        chk.grid(row=row, column=0, columnspan=2, sticky="w", padx=8, pady=4)
        self.vars[key] = var

    def _int_or(self, s, default):
        try:
            s = (s or "").strip()
            return int(s) if s != "" else default
        except Exception:
            return default

    def _float_or(self, s, default):
        try:
            s = (s or "").strip()
            return float(s) if s != "" else default
        except Exception:
            return default

    def log(self, msg: str):
        self.event_q.put(("log", msg))

    def set_health(self, state: str):
        style = "Status.OK.TLabel" if state == "OK" else "Status.Bad.TLabel"
        self.health_state = state
        self.health_lbl.config(text=f"health: {state}", style=style)

    # ------------------------------------------------------------------
    def _process_events(self):
        while True:
            try:
                kind, data = self.event_q.get_nowait()
            except queue.Empty:
                break
            if kind == "log":
                line = data.get("line") if isinstance(data, dict) else data
                self.log_text.insert("end", line + "\n")
                self.log_text.see("end")
            elif kind in {"options", "options_metrics"}:
                if "ok" in data and "ok200" not in data:
                    data["ok200"] = data.pop("ok")
                if "timeout" in data and "timeouts" not in data:
                    data["timeouts"] = data.pop("timeout")
                self.state["options"].update(data)
                now = time.monotonic()
                if data.get("last") == "200":
                    self.last_200_ts = now
                    self.fail_streak = 0
                    if self.health_state != "OK":
                        self.set_health("OK")
                        src = "monitor" if kind == "options_metrics" else "manual"
                        self.log(f"health: OK ({src})")
                else:
                    if data.get("last") and data.get("last") != "-":
                        self.fail_streak += 1
                    if (
                        (now - self.last_200_ts) > self.health_grace_s
                        or self.fail_streak >= self.fail_threshold
                    ):
                        if self.health_state != "FAIL":
                            self.set_health("FAIL")
                            src = "monitor" if kind == "options_metrics" else "manual"
                            self.log(f"health: FAIL ({src})")
            elif kind == "options_rx":
                self.state["options"]["rx"] = data
            elif kind == "uac":
                self.state["uac"].update(data)
            elif kind == "uas":
                self.state["uas"].update(data)
        self._refresh_status()
        self._refresh_buttons_state()
        self.after(200, self._process_events)

    def _refresh_status(self):
        opt = self.state["options"]
        if getattr(self, "options_thread", None) and self.options_thread.is_alive():
            self.monitor_status_lbl.config(
                text="monitor: ACTIVO", style="Status.OK.TLabel"
            )
        else:
            self.monitor_status_lbl.config(
                text="monitor: PARADO", style="Status.Warn.TLabel"
            )
        style_last = "Status.OK.TLabel"
        if opt.get("last") in {"timeout", "error"}:
            style_last = "Status.Bad.TLabel"
        elif opt.get("last") not in {"200", "-"}:
            style_last = "Status.Warn.TLabel"
        ok = opt.get("ok200", opt.get("ok", 0))
        tout = opt.get("timeouts", opt.get("timeout", 0))
        self.monitor_counts_lbl.config(
            text=(
                f"sent={opt.get('sent', 0)} 200={ok} other={opt.get('other', 0)} "
                f"timeout={tout} last={opt.get('last', '-')}"
            ),
            style=style_last,
        )
        self.monitor_rx_lbl.config(text=f"rx_options={opt.get('rx', 0)}")

        style = (
            "Status.OK.TLabel" if self.health_state == "OK" else "Status.Bad.TLabel"
        )
        self.health_lbl.config(text=f"health: {self.health_state}", style=style)
        counts = self.sm.active_counts()
        u = self.state["uac"]
        u["active"] = counts["uac"]
        self.uac_lbl.config(
            text=(
                f"UAC launched={u['launched']} active={u['active']} established={u['established']} "
                f"4xx={u['failed_4xx']} 5xx={u['failed_5xx']} canceled={u['canceled']} remote_bye={u['remote_bye']}"
            )
        )
        self.uas_lbl.config(text=f"UAS dialogs={counts['uas']}")
        if getattr(self, "uas_thread", None) and self.uas_thread.is_alive():
            self.uas_status_lbl.config(text="UAS: ACTIVO", style="Status.OK.TLabel")
        else:
            self.uas_status_lbl.config(text="UAS: PARADO", style="Status.Warn.TLabel")
        if getattr(self, "load_thread", None) and self.load_thread.is_alive():
            self.gen_status_lbl.config(text="Generador: EN MARCHA", style="Status.OK.TLabel")
        else:
            self.gen_status_lbl.config(text="Generador: PARADO", style="Status.Warn.TLabel")

    def update_button_states(self):
        role = self.vars.get("role", tk.StringVar(value="UAC")).get()
        dst = self.vars.get("dst_host", tk.StringVar()).get().strip()
        dport = self.vars.get("dst_port", tk.StringVar()).get().strip()
        resolvable = True
        if not dst:
            resolvable = False
        else:
            try:
                socket.gethostbyname(dst)
            except OSError:
                resolvable = False
        dest_ok = resolvable and dport.isdigit()

        interval_s = self.vars.get("interval", tk.StringVar()).get().strip()
        try:
            interval_ok = float(interval_s) > 0
        except ValueError:
            interval_ok = False

        self.opt_btn.state(["!disabled" if resolvable else "disabled"])

        if getattr(self, "options_thread", None) and self.options_thread.is_alive():
            self.mon_start_btn.state(["disabled"])
            self.mon_stop_btn.state(["!disabled"])
        else:
            enable_mon = dest_ok and interval_ok
            self.mon_start_btn.state(["!disabled" if enable_mon else "disabled"])
            self.mon_stop_btn.state(["disabled"])

        base_enabled = (
            self.health_state == "OK"
            or self.vars.get("ignore_health", tk.BooleanVar()).get()
        )
        if not dest_ok:
            base_enabled = False
        self.load_btn.state(["!disabled" if base_enabled else "disabled"])
        if hasattr(self, "load_tab_btn"):
            self.load_tab_btn.state(["!disabled" if base_enabled else "disabled"])

        if role == "UAS":
            self.call_btn.state(["disabled"])
            for k in [
                "from_number",
                "from_domain",
                "from_display",
                "to_number",
                "to_domain",
                "from_uri",
                "to_uri",
            ]:
                if k in self.widgets:
                    self.widgets[k].config(state="disabled")
        else:
            for k in [
                "from_number",
                "from_domain",
                "from_display",
                "to_number",
                "to_domain",
                "from_uri",
                "to_uri",
            ]:
                if k in self.widgets:
                    self.widgets[k].config(state="normal")
            to_uri = self.vars.get("to_uri", tk.StringVar()).get().strip()
            to_number = self.vars.get("to_number", tk.StringVar()).get().strip()
            to_domain = self.vars.get("to_domain", tk.StringVar()).get().strip()
            identity_ok = bool(to_uri) or (to_number and to_domain)
            call_enabled = dest_ok and identity_ok
            if (
                self.vars.get("require_health_call", tk.BooleanVar(value=True)).get()
                and self.health_state != "OK"
            ):
                call_enabled = False
            self.call_btn.state(["!disabled" if call_enabled else "disabled"])

        counts = self.sm.active_counts()
        self.bye_uac_btn.state(["!disabled" if counts["uac"] > 0 else "disabled"])
        self.bye_uas_btn.state(["!disabled" if counts["uas"] > 0 else "disabled"])

    def _set_uac_buttons(self, active: bool):
        try:
            self.call_btn.configure(state=("normal" if active else "disabled"))
        except Exception:
            pass

    def _can_enable_generator(self):
        if self.role_var.get().lower() != "uac":
            return False
        if getattr(self, "_uac_running", False):
            return False
        try:
            calls = self._int_or(self.entry_calls.get(), 1)
            dst_host = self.entry_dst_host.get().strip()
            dst_port = self._int_or(self.entry_dst_port.get(), 5060)
            src_port_base = self._int_or(self.entry_src_port_base.get(), 5062)
            src_port_step = self._int_or(self.entry_src_port_step.get(), 10)
            rtp_port_step = self._int_or(self.entry_rtp_port_step.get(), 2)
            return (
                calls >= 1
                and bool(dst_host)
                and dst_port > 0
                and src_port_base > 0
                and src_port_step > 0
                and rtp_port_step > 0
            )
        except Exception:
            return False

    def _refresh_buttons_state(self):
        self.update_button_states()
        sm = getattr(self, "_sm_for_gui", None)
        running = bool(getattr(self, "_uac_running", False))
        try:
            self.call_btn.configure(state=("disabled" if running else "normal"))
        except Exception:
            pass
        try:
            uac_has = sm and sm.uac_active_count() > 0
            self.bye_uac_btn.configure(state=("normal" if uac_has else "disabled"))
        except Exception:
            pass
        try:
            uas_has = sm and sm.uas_active_count() > 0
            self.bye_uas_btn.configure(state=("normal" if uas_has else "disabled"))
        except Exception:
            pass
        try:
            enable_gen = self._can_enable_generator()
            self.load_btn.configure(state=("normal" if enable_gen else "disabled"))
            if hasattr(self, "load_tab_btn"):
                self.load_tab_btn.configure(state=("normal" if enable_gen else "disabled"))
        except Exception:
            pass

    # ------------------------------------------------------------------
    def get_config(self):
        cfg = {k: v.get() for k, v in self.vars.items()}
        try:
            for key in [
                "src_port",
                "dst_port",
                "rtp_port_base",
                "calls",
                "rate",
                "rtp_stats_every",
                "max_active",
                "number_step",
                "pad_width",
                "src_port_base",
                "src_port_step",
                "rtp_port_step",
                "interval",
                "timeout",
                "cseq_start",
            ]:
                if key in cfg and cfg[key] != "":
                    if key in {"rate", "rtp_stats_every", "interval", "timeout"}:
                        cfg[key] = float(cfg[key])
                    else:
                        cfg[key] = int(cfg[key])
            if cfg.get("rtp_port_base"):
                rtp = int(cfg["rtp_port_base"])
                if rtp % 2:
                    rtp += 1
                    cfg["rtp_port_base"] = rtp
                    self.vars["rtp_port_base"].set(str(rtp))
                    logging.info(
                        "rtp_port_base debe ser par; ajustado a %s", rtp
                    )
        except ValueError as exc:
            messagebox.showerror("Valor inválido", str(exc))
            return None
        return cfg

    def _get_load_cfg(self):
        cfg = self.get_config()
        if not cfg:
            return None
        cfg["calls"] = self._int_or(self.entry_calls.get(), 1)
        cfg["rate"] = self._float_or(self.entry_rate.get(), 1.0)
        cfg["max_active"] = self._int_or(self.entry_max_active.get(), cfg["calls"])
        cfg["from_number_start"] = (self.entry_from_start.get() or "1001").strip()
        cfg["to_number_start"] = (self.entry_to_start.get() or "2001").strip()
        cfg["number_step"] = self._int_or(self.entry_number_step.get(), 1)
        cfg["pad_width"] = self._int_or(self.entry_pad_width.get(), 0)
        cfg["src_port_base"] = self._int_or(self.entry_src_port_base.get(), 5062)
        cfg["src_port_step"] = self._int_or(self.entry_src_port_step.get(), 10)
        cfg["rtp_port_step"] = self._int_or(self.entry_rtp_port_step.get(), 2)
        return cfg

    def start_options_monitor(self):
        if getattr(self, "options_thread", None) and self.options_thread.is_alive():
            return

        bind_ip = (self.vars.get("bind_ip").get() or "0.0.0.0").strip()
        dst_host = (self.vars.get("dst_host").get() or "").strip()
        try:
            dst_port = int(self.vars.get("dst_port").get() or 0)
        except Exception:
            dst_port = 0
        try:
            src_port = int(self.vars.get("src_port").get() or 0)
        except Exception:
            src_port = 0
        try:
            interval = float(self.vars.get("interval").get() or 1.0)
        except Exception:
            interval = 1.0
        try:
            timeout = float(self.vars.get("timeout").get() or 2.0)
        except Exception:
            timeout = 2.0
        try:
            cseq_start = int(self.vars.get("cseq_start").get() or 1)
        except Exception:
            cseq_start = 1

        use_src = bool(self.vars.get("use_src_port_options").get())
        reply_opt = bool(self.vars.get("reply_options").get())

        if interval <= 0:
            interval = 1.0
        if timeout <= 0:
            timeout = 2.0
        if cseq_start < 1:
            cseq_start = 1
        if not dst_host or dst_port <= 0:
            logging.info("OPTIONS: destino incompleto (host/puerto).")
            return

        sock = self._ensure_shared_sock(bind_ip, src_port if use_src else 0)

        def pub(payload):
            """Publish events coming from monitor thread to GUI queue."""
            typ = payload.pop("type")
            if typ == "options_rx":
                self.event_q.put((typ, payload.get("count", 0)))
            else:
                self.event_q.put((typ, payload))

        self.options_thread = OptionsMonitorThread(
            sock=sock,
            dst_host=dst_host,
            dst_port=dst_port,
            interval=interval,
            timeout=timeout,
            cseq_start=cseq_start,
            reply_options=reply_opt,
            publish_event=pub,
        )
        self.options_thread.start()
        self.monitor_status_lbl.config(text="monitor: ACTIVO", style="Status.OK.TLabel")
        logging.info(
            f"OPTIONS monitor started dst={dst_host}:{dst_port} every {interval}s "
            f"from {sock.getsockname()[0]}:{sock.getsockname()[1]} "
            f"{'(responder ON)' if reply_opt else '(responder OFF)'}"
        )
        self._refresh_buttons_state()

    def stop_options_monitor(self, close_sock: bool = True):
        if getattr(self, "options_thread", None):
            self.options_thread.stop_evt.set()
            self.options_thread.join(timeout=1)
            self.options_thread = None
        if close_sock:
            self._close_shared_sock()
        self.monitor_status_lbl.config(text="monitor: PARADO", style="Status.Warn.TLabel")
        self._refresh_buttons_state()

    def reset_options_monitor(self):
        self.state["options"] = {
            "sent": 0,
            "ok200": 0,
            "other": 0,
            "timeouts": 0,
            "last": "-",
            "rx": 0,
        }
        self.event_q.put(("options_metrics", self.state["options"].copy()))
        self.fail_streak = 0

    def copy_cli_command(self):
        bind_ip = (self.vars.get("bind_ip").get() or "0.0.0.0").strip()
        dst_host = (self.vars.get("dst_host").get() or "").strip()
        try:
            src_port = int(self.vars.get("src_port").get() or 0)
        except Exception:
            src_port = 0
        try:
            dst_port = int(self.vars.get("dst_port").get() or 0)
        except Exception:
            dst_port = 0
        try:
            interval = float(self.vars.get("interval").get() or 1.0)
        except Exception:
            interval = 1.0
        try:
            cseq = int(self.vars.get("cseq_start").get() or 1)
        except Exception:
            cseq = 1
        reply_opt = bool(self.vars.get("reply_options").get())
        use_src = bool(self.vars.get("use_src_port_options").get())
        if not use_src:
            src_port = 0
        parts = [
            "python",
            "app.py",
            "--single-socket",
            "--service",
            "--reply-options" if reply_opt else "",
            "--bind-ip",
            bind_ip,
            "--src-port",
            str(src_port),
            "--dst",
            dst_host,
            "--dst-port",
            str(dst_port),
            "--interval",
            str(interval),
            "--cseq-start",
            str(cseq),
        ]
        cmd = " ".join(p for p in parts if p)
        self.clipboard_clear()
        self.clipboard_append(cmd)
        self.event_q.put(("log", f"CLI: {cmd}"))
        self.event_q.put(("log", "Comando copiado al portapapeles"))

    def start_options(self):
        cfg = self.get_config()
        t = threading.Thread(target=options_worker, args=(cfg, self.event_q))
        t.daemon = True
        t.start()

    def on_uac_call_clicked(self):
        if getattr(self, "_uac_running", False):
            return
        self._uac_running = True
        self._set_uac_buttons(active=False)
        t = threading.Thread(target=self._uac_worker, daemon=True)
        t.start()

    def _uac_worker(self):
        try:
            result = self._do_uac_call_once()
            if result is not None:
                self.log(f"UAC: resultado {result}")
        finally:
            self._uac_running = False
            self.after(0, self._refresh_buttons_state)

    def _do_uac_call_once(self):
        dst_host = (self.vars.get("dst_host").get() or "").strip()
        try:
            dst_port = int(self.vars.get("dst_port").get() or 0)
        except Exception:
            dst_port = 0
        if not dst_host or not dst_port:
            self.log("UAC: faltan dst_host/dst_port")
            return

        from_num = (self.vars.get("from_number").get() or "").strip()
        from_dom = (self.vars.get("from_domain").get() or "").strip()
        to_num = (self.vars.get("to_number").get() or "").strip()
        to_dom = (self.vars.get("to_domain").get() or "").strip()
        from_uri = (self.vars.get("from_uri").get() or "") or f"{from_num}@{from_dom}"
        to_uri = (self.vars.get("to_uri").get() or "") or f"{to_num}@{to_dom}"

        codecs_csv = (self.vars.get("codecs").get() or "pcmu,pcma")
        codec_names = [c.strip().lower() for c in codecs_csv.split(",") if c.strip()]
        codec_pts = []
        for name in codec_names:
            pt = PT_FROM_CODEC_NAME.get(name)
            if pt is not None:
                codec_pts.append((pt, name.upper()))
        if not codec_pts:
            codec_pts = [(0, "PCMU"), (8, "PCMA")]
        try:
            rtp_base = int(self.vars.get("rtp_port_base").get() or 40000)
        except Exception:
            rtp_base = 40000
        try:
            tone_hz = int(self.vars.get("tone_hz").get() or 0)
        except Exception:
            tone_hz = 0
        send_silence = bool(self.vars.get("send_silence").get())
        try:
            stats_every = float(self.vars.get("rtp_stats_every").get() or 2.0)
        except Exception:
            stats_every = 2.0

        ring_timeout = float(self.vars["ring_timeout"].get()) if "ring_timeout" in self.vars else 10.0
        wait_bye = bool(self.vars.get("wait_bye").get())

        sock = self._ensure_shared_sock()
        local_ip, _ = sock.getsockname()
        if local_ip == "0.0.0.0":
            try:
                sock.connect((dst_host, dst_port))
                local_ip = sock.getsockname()[0]
                sock.connect(("0.0.0.0", 0))
            except Exception:
                pass

        sdp_offer = build_sdp_offer(local_ip, rtp_base, codec_pts).decode()

        try:
            from sip_manager import SIPManager
        except Exception:
            self.log("UAC: no se pudo importar SIPManager")
            return

        sm = SIPManager(sock=sock, logger=logging.getLogger("gui"))
        self.sm = sm
        self._sm_for_gui = sm

        self.log(
            f"UAC: llamando a sip:{to_uri} via {dst_host}:{dst_port} "
            f"sent-by={sock.getsockname()[0]}:{sock.getsockname()[1]} "
            f"RTP={local_ip}:{rtp_base} codecs={','.join(n for _, n in codec_pts)}"
        )

        try:
            call_id, result, setup_ms, talk_s = sm.place_call(
                dst_host=dst_host,
                dst_port=dst_port,
                from_uri=f"sip:{from_uri}",
                to_uri=f"sip:{to_uri}",
                sdp_offer=sdp_offer,
                codecs=codec_pts,
                rtp_port=rtp_base,
                rtp_port_forced=True,
                tone_hz=tone_hz,
                send_silence=send_silence,
                stats_interval=stats_every,
                ring_timeout=ring_timeout,
                wait_bye=wait_bye,
            )
            self.log(
                f"UAC: call_id={call_id} result={result} setup={setup_ms}ms talk={talk_s}s"
            )
            return result
        except OSError as e:
            if getattr(e, "errno", None) == 111:
                self.log(
                    f"UAC: destino no escucha en {dst_host}:{dst_port} (Connection refused)"
                )
            else:
                self.log(f"UAC: error de socket: {e}")
            return "socket-error"
        except Exception as e:  # noqa: BLE001
            self.log(f"UAC: excepción: {e}")
            return "exception"

    def start_call(self):
        cfg = self.get_config()
        if not cfg:
            return
        sock = self._ensure_shared_sock()
        self.sm = SIPManager(sock=sock)
        t = threading.Thread(target=call_worker, args=(cfg, self.event_q, self.sm))
        t.daemon = True
        t.start()

    def start_load(self):
        uas_active = getattr(self, "uas_thread", None) and self.uas_thread.is_alive()
        if (self.health_state != "OK" or not uas_active) and not self.vars["ignore_health"].get():
            self.log(
                "Generador: UAS no activo o sin health; marca 'ignorar health' o arranca UAS."
            )
            return
        cfg = self._get_load_cfg()
        if not cfg:
            return
        sock = self._ensure_shared_sock()
        self.sm = SIPManager(sock=sock)
        self.stop_event.clear()
        t = threading.Thread(target=load_worker, args=(cfg, self.event_q, self.stop_event, self.sm))
        t.daemon = True
        t.start()
        self.load_thread = t
        self._refresh_buttons_state()

    def toggle_uas(self):
        if getattr(self, "uas_thread", None) and self.uas_thread.is_alive():
            self.on_stop_uas()
            self.uas_btn.config(text="Iniciar UAS")
        else:
            cfg = self.get_config()
            if not cfg:
                return
            sock = self._ensure_shared_sock()
            sm = SIPManager(sock=sock)
            self.sm = sm
            self._sm_for_gui = sm
            self.uas_stop = threading.Event()
            self.stop_event.clear()
            self.uas_thread = threading.Thread(
                target=uas_worker,
                args=(cfg, self.event_q, self.uas_stop, sm),
                daemon=True,
            )
            self.uas_thread.start()
            self.uas_btn.config(text="Detener UAS")
            self._refresh_buttons_state()

    def on_stop_uas(self):
        if getattr(self, "uas_stop", None):
            self.uas_stop.set()
        if getattr(self, "uas_thread", None):
            self.uas_thread.join(timeout=1.0)
            self.uas_thread = None
        sm = getattr(self, "_sm_for_gui", None)
        if sm:
            sm.bye_all_uas()
        try:
            self.uas_btn.config(text="Iniciar UAS")
        except Exception:
            pass
        self._refresh_buttons_state()
        self.log("UAS service stopped")

    def stop_all(self):
        sm = getattr(self, "_sm_for_gui", None)
        if sm:
            sm.bye_all_uac()
        self.stop_event.set()
        self.stop_options_monitor(close_sock=False)
        if getattr(self, "load_thread", None):
            self.load_thread.join(timeout=1)
            self.load_thread = None
        self.on_stop_uas()
        self.after(0, self._refresh_buttons_state)
        self.log("Detenido todo")

    def _ensure_shared_sock(self, bind_ip=None, src_port=None):
        """Crea (si no existe) y devuelve el socket UDP compartido bind al bind_ip/src_port."""
        if getattr(self, "_shared_sock", None):
            return self._shared_sock
        bind_ip = (
            bind_ip
            or (self.vars.get("bind_ip").get() if self.vars.get("bind_ip") else "0.0.0.0")
            or "0.0.0.0"
        ).strip()
        try:
            src_port = int(
                src_port
                if src_port is not None
                else (self.vars.get("src_port").get() or 0)
            )
        except Exception:
            src_port = 0
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((bind_ip, src_port))
        s.settimeout(2.0)
        self._shared_sock = s
        return s

    def _close_shared_sock(self):
        s = getattr(self, "_shared_sock", None)
        if s:
            try:
                s.close()
            except Exception:
                pass
        self._shared_sock = None

    def on_bye_all_uac(self):
        sm = getattr(self, "_sm_for_gui", None)
        if sm:
            sm.bye_all_uac()
        # ensure the call button is re-enabled even if the worker got stuck
        self._uac_running = False
        self.after(0, self._refresh_buttons_state)
        self.log("BYE UAC enviado.")

    def on_bye_all_uas(self):
        sm = getattr(self, "_sm_for_gui", None)
        if sm:
            sm.bye_all_uas()
        self.after(0, self._refresh_buttons_state)
        self.log("BYE UAS enviado.")

    def save_log(self):
        path = filedialog.asksaveasfilename(defaultextension=".log")
        if path:
            with open(path, "w", encoding="utf8") as f:
                f.write(self.log_text.get("1.0", "end"))

    def on_close(self):
        if messagebox.askokcancel("Salir", "¿Cerrar la aplicación?"):
            self.stop_all()
            cfg = self.get_config()
            if cfg:
                save_config(cfg)
            self.destroy()



class OptionsMonitorThread(threading.Thread):
    def __init__(
        self,
        *,
        sock,
        dst_host,
        dst_port,
        interval,
        timeout,
        cseq_start,
        reply_options: bool,
        publish_event,
    ):
        super().__init__(daemon=True)
        self.sock = sock
        self.dst = (dst_host, int(dst_port))
        self.interval = max(float(interval or 1.0), 0.05)
        self.timeout = max(float(timeout or 2.0), 0.1)
        self.cseq = int(cseq_start or 1)
        self.reply = bool(reply_options)
        self.publish_event = publish_event
        self.stop_evt = threading.Event()
        self.sent = self.ok200 = self.other = self.timeouts = 0
        self.last = None
        self.rx = 0
        self.local_ip = None

    def run(self):
        sock = self.sock
        sock.settimeout(0.2)
        next_send = 0.0
        pending: tuple[int, float] | None = None
        while not self.stop_evt.is_set():
            now = time.monotonic()
            if now >= next_send:
                local_port = sock.getsockname()[1]
                try:
                    tmp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    tmp.connect(self.dst)
                    self.local_ip = tmp.getsockname()[0]
                except Exception:
                    self.local_ip = sock.getsockname()[0]
                finally:
                    try:
                        tmp.close()
                    except Exception:
                        pass
                call_id, payload = build_options(
                    self.dst[0], self.local_ip, local_port, "mon", self.cseq
                )
                sock.sendto(payload, self.dst)
                self.sent += 1
                pending = (self.cseq, now)
                self.cseq += 1
                next_send = now + self.interval
                if self.publish_event:
                    self.publish_event(
                        {
                            "type": "options_metrics",
                            "sent": self.sent,
                            "ok200": self.ok200,
                            "other": self.other,
                            "timeouts": self.timeouts,
                            "last": self.last or "-",
                        }
                    )
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                data = None
            if data:
                text = data.decode(errors="ignore")
                if text.startswith("OPTIONS") and self.reply:
                    start, headers = parse_headers(data)
                    via = headers.get("via")
                    fr = headers.get("from")
                    to = headers.get("to")
                    call_id = headers.get("call-id")
                    cseq_hdr = headers.get("cseq")
                    if all([via, fr, to, call_id, cseq_hdr]):
                        if "tag=" not in to.lower():
                            to = f"{to};tag=resp"
                        headers_resp = {
                            "Via": via,
                            "From": fr,
                            "To": to,
                            "Call-ID": call_id,
                            "CSeq": cseq_hdr,
                            "Contact": f"<sip:dimitri@{self.local_ip}:{sock.getsockname()[1]}>",
                            "User-Agent": "Dimitri-4000/0.1",
                            "Allow": "INVITE, ACK, CANCEL, OPTIONS, BYE",
                            "Accept": "application/sdp",
                        }
                        sock.sendto(build_response(200, "OK", headers_resp), addr)
                        self.rx += 1
                        if self.publish_event:
                            self.publish_event(
                                {
                                    "type": "log",
                                    "line": f"Responded 200 OK to OPTIONS from {addr[0]}:{addr[1]}",
                                }
                            )
                            self.publish_event({"type": "options_rx", "count": self.rx})
                elif (
                    pending
                    and addr[0] == self.dst[0]
                    and text.startswith("SIP/2.0")
                ):
                    if text.startswith("SIP/2.0 200"):
                        self.ok200 += 1
                        self.last = "200"
                    else:
                        self.other += 1
                        self.last = "other"
                    pending = None
                    if self.publish_event:
                        self.publish_event(
                            {
                                "type": "options_metrics",
                                "sent": self.sent,
                                "ok200": self.ok200,
                                "other": self.other,
                                "timeouts": self.timeouts,
                                "last": self.last,
                            }
                        )
            now = time.monotonic()
            if pending and (now - pending[1]) >= self.timeout:
                self.timeouts += 1
                self.last = "timeout"
                pending = None
                if self.publish_event:
                    self.publish_event(
                        {
                            "type": "options_metrics",
                            "sent": self.sent,
                            "ok200": self.ok200,
                            "other": self.other,
                            "timeouts": self.timeouts,
                            "last": self.last,
                        }
                    )
            if self.stop_evt.wait(0.05):
                break

def options_worker(cfg, event_q):
    counters = {"sent": 0, "ok": 0, "other": 0, "timeout": 0, "last": "-"}
    sm = SIPManager(protocol="udp")
    dst = cfg.get("dst_host")
    dport = int(cfg.get("dst_port", 5060))
    bind_ip = cfg.get("bind_ip") or None
    src_port = int(cfg.get("src_port", "0") or 0)
    if not cfg.get("use_src_port_options", True):
        src_port = 0
    for _ in range(3):
        counters["sent"] += 1
        try:
            code, _, _ = sm.send_request(
                dst_host=dst,
                dst_port=dport,
                bind_ip=bind_ip,
                bind_port=src_port,
            )
        except OSError as exc:
            if getattr(exc, "errno", None) == 111:
                event_q.put(("log", f"Destino no escucha en {dst}:{dport}"))
            else:
                event_q.put(("log", f"OPTIONS error: {exc}"))
            counters["other"] += 1
            counters["last"] = "error"
        else:
            if code is None:
                counters["timeout"] += 1
                counters["last"] = "timeout"
            elif code == 200:
                counters["ok"] += 1
                counters["last"] = "200"
            else:
                counters["other"] += 1
                counters["last"] = str(code)
        counters["ts"] = time.monotonic()
        event_q.put(("options", counters.copy()))
        time.sleep(0.5)
    event_q.put(("log", "OPTIONS test finished"))


def call_worker(cfg, event_q, sm):
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
    dst = cfg.get("dst_host")
    dport = int(cfg.get("dst_port", 5060))
    codec_names = [c.strip() for c in cfg.get("codecs", "pcmu,pcma").split(",") if c.strip()]
    codecs = []
    for name in codec_names:
        pt = PT_FROM_CODEC_NAME.get(name.lower())
        if pt is not None:
            codecs.append((pt, name.upper()))
    if not codecs:
        codecs = [(0, "PCMU"), (8, "PCMA")]
    tone = int(cfg.get("tone_hz", "0") or 0)
    try:
        _, result, _, _ = sm.place_call(
            dst_host=dst,
            dst_port=dport,
            from_number=cfg.get("from_number") or "1000",
            from_domain=cfg.get("from_domain") or None,
            from_display=cfg.get("from_display") or None,
            to_number=cfg.get("to_number") or "1001",
            to_domain=cfg.get("to_domain") or None,
            codecs=codecs,
            rtp_port=int(cfg.get("rtp_port_base", "40000")),
            rtp_port_forced=True,
            tone_hz=tone or None,
            send_silence=cfg.get("send_silence", False),
            symmetric=cfg.get("symmetric_rtp", False),
            stats_interval=float(cfg.get("rtp_stats_every", "2.0")),
            wait_bye=cfg.get("wait_bye", True),
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


def load_worker(cfg, event_q, stop_event, sm):
    try:
        args = SimpleNamespace(
            dst=cfg.get("dst_host"),
            dst_port=cfg.get("dst_port", 5060),
            host=None,
            port=None,
            to_uri_pattern=None,
            to_number_start=cfg.get("to_number_start") or "2001",
            from_number_start=cfg.get("from_number_start") or "1001",
            number_step=cfg.get("number_step", 1),
            pad_width=cfg.get("pad_width", 0),
            from_number=None,
            from_user="dimitri",
            to_domain_load=cfg.get("to_domain") or cfg.get("dst_host"),
            from_domain_load=cfg.get("from_domain") or (cfg.get("bind_ip") or ""),
            src_port_base=cfg.get("src_port_base", 0),
            src_port_step=cfg.get("src_port_step", 10),
            rtp_port_base=cfg.get("rtp_port_base", 40000),
            rtp_port_step=cfg.get("rtp_port_step", 2),
            bind_ip=cfg.get("bind_ip") or None,
            timeout=2.0,
            ring_timeout=15.0,
            talk_time=0.0,
            wait_bye=False,
            max_call_time=0.0,
            codecs=[(0, "PCMU")],
            rtcp=False,
            rtp_tone=None,
            rtp_send_silence=False,
            symmetric_rtp=False,
            rtp_stats_every=cfg.get("rtp_stats_every", 2.0),
            calls=cfg.get("calls", 1),
            rate=cfg.get("rate", 1.0),
            max_active=cfg.get("max_active", 1),
        )
        if (
            args.calls < 1
            or not args.dst
            or args.dst_port <= 0
            or args.src_port_base <= 0
            or args.src_port_step <= 0
            or args.rtp_port_step <= 0
        ):
            event_q.put(("log", "Generador: parámetros inválidos; abortando"))
            return
    except Exception as exc:  # noqa: BLE001
        event_q.put(("log", f"Generador: parámetros inválidos ({exc})"))
        return

    def stats_cb(snapshot):
        event_q.put(("uac", snapshot))

    try:
        run_load_generator(args, sm, stats_cb=stats_cb)
    except Exception as exc:  # noqa: BLE001
        event_q.put(("log", f"Generador: abortado ({exc})"))
        return
    event_q.put(("log", "Load finished"))


def uas_worker(cfg, event_q, stop_event, sm):
    sock = sm.sock
    if not sock:
        event_q.put(("log", "UAS socket not available"))
        return
    sock.settimeout(0.5)
    codec_names = [c.strip() for c in cfg.get("codecs", "pcmu,pcma").split(",") if c.strip()]
    codecs = []
    for name in codec_names:
        pt = PT_FROM_CODEC_NAME.get(name.lower())
        if pt is not None:
            codecs.append((pt, name.upper()))
    if not codecs:
        codecs = [(0, "PCMU"), (8, "PCMA")]
    local_ip = sock.getsockname()[0]
    rtp_port = int(cfg.get("rtp_port_base", "40000"))
    try:
        tone_hz = int(cfg.get("tone_hz", "0"))
    except Exception:
        tone_hz = 0
    send_silence = bool(cfg.get("send_silence", False))
    try:
        stats_every = float(cfg.get("rtp_stats_every", "2.0") or 2.0)
    except Exception:
        stats_every = 2.0
    event_q.put(("log", "UAS service started"))
    try:
        while not stop_event.is_set():
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            start, headers = parse_headers(data)
            if not start:
                continue
            if start.startswith("INVITE "):
                try:
                    via = headers["via"]
                    fr = headers["from"]
                    to = headers["to"]
                    call_id = headers["call-id"]
                    cseq_hdr = headers["cseq"]
                except KeyError:
                    continue
                remote_tag = None
                if "tag=" in fr.lower():
                    remote_tag = fr.split("tag=")[1].split(";", 1)[0]
                local_tag = sm._new_tag()
                to_resp = f"{to};tag={local_tag}"
                headers_base = {
                    "Via": via,
                    "From": fr,
                    "To": to_resp,
                    "Call-ID": call_id,
                    "CSeq": cseq_hdr,
                }
                sock.sendto(build_trying(headers_base), addr)
                sock.sendto(build_ringing(headers_base), addr)
                body = b""
                if b"\r\n\r\n" in data:
                    body = data.split(b"\r\n\r\n", 1)[1]
                sdp_info = parse_sdp(body)
                remote_pts = sdp_info.get("pts") or []
                local_pts = [pt for pt, _ in codecs]
                if remote_pts:
                    common = [pt for pt in remote_pts if pt in local_pts]
                    if not common:
                        headers488 = headers_base.copy()
                        sock.sendto(build_response(488, "Not Acceptable Here", headers488), addr)
                        continue
                    use_codecs = [(pt, name) for pt, name in codecs if pt == common[0]]
                else:
                    use_codecs = codecs
                try:
                    rem_ip, rem_port = parse_sdp_ip_port(body)
                except ValueError:
                    rem_ip, rem_port = addr[0], rtp_port
                sdp_ans = build_sdp(local_ip, rtp_port, use_codecs)
                headers200 = headers_base.copy()
                headers200.update(
                    {
                        "Contact": f"<sip:dimitri@{local_ip}:{sock.getsockname()[1]}>",
                        "Allow": "INVITE, ACK, CANCEL, OPTIONS, BYE",
                        "Accept": "application/sdp",
                        "Content-Type": "application/sdp",
                    }
                )
                sock.sendto(build_200(headers200, sdp_ans), addr)
                rtp = None
                if send_silence or tone_hz > 0:
                    try:
                        rtp = RtpSession(local_ip, rtp_port, use_codecs[0][0], forced=True)
                        rtp.tone_hz = tone_hz
                        rtp.send_silence = send_silence and not tone_hz
                        rtp.stats_interval = stats_every
                        rtp.start(rem_ip, rem_port)
                    except Exception:
                        rtp = None
                sm.uas_dialogs[call_id] = {
                    "dst": addr,
                    "from_uri": to.split(";", 1)[0],
                    "from_tag": local_tag,
                    "to_uri": fr.split(";", 1)[0],
                    "to_tag": remote_tag or "",
                    "call_id": call_id,
                    "cseq_next": 1,
                    "rtp": rtp,
                }
                event_q.put(("uas", {"dialogs": len(sm.uas_dialogs)}))
            elif start.startswith("BYE "):
                try:
                    via = headers["via"]
                    fr = headers["from"]
                    to = headers["to"]
                    call_id = headers["call-id"]
                    cseq_hdr = headers["cseq"]
                except KeyError:
                    continue
                d = sm.uas_dialogs.pop(call_id, None)
                sm.logger.info(
                    f"RX BYE call_id={call_id} side=UAS -> sending 200 OK & stopping RTP"
                )
                to_resp = to
                if d:
                    to_resp = f"{d['from_uri']};tag={d['from_tag']}"
                    sm._safe_stop_rtp(d)
                    event_q.put(("uas", {"dialogs": len(sm.uas_dialogs)}))
                headers200 = {
                    "Via": via,
                    "From": fr,
                    "To": to_resp,
                    "Call-ID": call_id,
                    "CSeq": cseq_hdr,
                }
                sock.sendto(build_200(headers200), addr)
    finally:
        event_q.put(("log", "UAS service stopped"))


def bye_all_worker(sm, role, event_q):
    count = sm.bye_all(role)
    event_q.put(("log", f"bye_all({role}) sent {count} BYE(s)"))


def main(args=None):
    App(args).mainloop()
