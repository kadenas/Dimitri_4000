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

from sip_manager import SIPManager, build_response, parse_headers
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
            "options": {"sent": 0, "ok": 0, "other": 0, "timeout": 0, "last": "-", "rx": 0},
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
        self.health_ok = False
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

    # ------------------------------------------------------------------
    def _build_ui(self, cfg):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Status.OK.TLabel", background="#b6f7a5")
        style.configure("Status.Bad.TLabel", background="#f7b6b6")
        style.configure("Status.Warn.TLabel", background="#f7e7a5")

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
        self._add_entry(lf_dest, "dst_port", 1, cfg)

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
        ttk.Radiobutton(lf_mode, text="UAC", variable=self.vars["role"], value="UAC", command=self.update_button_states).grid(row=0, column=0, sticky="w")
        ttk.Radiobutton(lf_mode, text="UAS", variable=self.vars["role"], value="UAS", command=self.update_button_states).grid(row=0, column=1, sticky="w")
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

        # ------------------ Load tab ------------------
        load = ttk.Frame(nb)
        nb.add(load, text="Carga")

        lf_load = ttk.LabelFrame(load, text="Parámetros de carga")
        lf_load.grid(row=0, column=0, sticky="nsew", padx=8, pady=4)
        self._add_check(lf_load, "load", 0, cfg, text="load")
        self._add_entry(lf_load, "calls", 1, cfg)
        self._add_entry(lf_load, "rate", 2, cfg)
        self._add_entry(lf_load, "max_active", 3, cfg)
        self._add_entry(lf_load, "from_number_start", 4, cfg)
        self._add_entry(lf_load, "to_number_start", 5, cfg)
        self._add_entry(lf_load, "number_step", 6, cfg)
        self._add_entry(lf_load, "pad_width", 7, cfg)
        self._add_entry(lf_load, "src_port_base", 8, cfg)
        self._add_entry(lf_load, "src_port_step", 9, cfg)
        self._add_entry(lf_load, "rtp_port_step", 10, cfg)
        self._add_check(lf_load, "ignore_health", 11, cfg, text="ignorar health")
        self.load_tab_btn = ttk.Button(load, text="Iniciar Generador", command=self.start_load)
        self.load_tab_btn.grid(row=1, column=0, pady=8)

        # separator and main button row
        ttk.Separator(self, orient="horizontal").pack(fill="x", pady=4)
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill="x")
        self.opt_btn = ttk.Button(btn_frame, text="Probar OPTIONS", command=self.start_options)
        self.uas_btn = ttk.Button(btn_frame, text="Iniciar UAS", command=self.toggle_uas)
        self.call_btn = ttk.Button(btn_frame, text="Llamada UAC", command=self.start_call)
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
        self.update_button_states()

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
            parent, text=text or key, variable=var, command=self.update_button_states
        )
        chk.grid(row=row, column=0, columnspan=2, sticky="w", padx=8, pady=4)
        self.vars[key] = var

    # ------------------------------------------------------------------
    def _process_events(self):
        while True:
            try:
                kind, data = self.event_q.get_nowait()
            except queue.Empty:
                break
            if kind == "log":
                self.log_text.insert("end", data + "\n")
                self.log_text.see("end")
            elif kind in {"options", "options_metrics"}:
                self.state["options"].update(data)
                self.health_ok = (
                    self.state["options"].get("ok", 0) > 0
                    and self.state["options"].get("other", 0) == 0
                    and self.state["options"].get("timeout", 0) == 0
                )
            elif kind == "options_rx":
                self.state["options"]["rx"] = data
            elif kind == "uac":
                self.state["uac"].update(data)
            elif kind == "uas":
                self.state["uas"].update(data)
        self._refresh_status()
        self.update_button_states()
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
        self.monitor_counts_lbl.config(
            text=(
                f"sent={opt['sent']} 200={opt['ok']} other={opt['other']} "
                f"timeout={opt['timeout']} last={opt.get('last', '-')}"
            ),
            style=style_last,
        )
        self.monitor_rx_lbl.config(text=f"rx_options={opt.get('rx', 0)}")

        style = "Status.OK.TLabel" if self.health_ok else "Status.Bad.TLabel"
        self.health_lbl.config(
            text=f"health: {'OK' if self.health_ok else 'FAIL'}",
            style=style,
        )
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

        base_enabled = self.health_ok or self.vars.get("ignore_health", tk.BooleanVar()).get()
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
                and not self.health_ok
            ):
                call_enabled = False
            self.call_btn.state(["!disabled" if call_enabled else "disabled"])

        counts = self.sm.active_counts()
        self.bye_uac_btn.state(["!disabled" if counts["uac"] > 0 else "disabled"])
        self.bye_uas_btn.state(["!disabled" if counts["uas"] > 0 else "disabled"])

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

        send_from_port = src_port if use_src else 0
        reply_on_port = src_port if reply_opt else 0

        self.options_thread = OptionsMonitorWorker(
            bind_ip,
            send_from_port,
            dst_host,
            dst_port,
            interval,
            timeout,
            cseq_start,
            reply_opt,
            self.event_q,
        )
        self.options_thread.start()
        if reply_opt:
            self.options_responder = OptionsResponder(bind_ip, reply_on_port, self.event_q)
            self.options_responder.start()
        self.monitor_status_lbl.config(text="monitor: ACTIVO", style="Status.OK.TLabel")
        logging.info(
            f"OPTIONS monitor started dst={dst_host}:{dst_port} every {interval}s "
            f"from {bind_ip}:{send_from_port or 'ephemeral'} "
            f"{'(responder ON)' if reply_opt else '(responder OFF)'}"
        )
        self.update_button_states()

    def stop_options_monitor(self):
        if getattr(self, "options_thread", None):
            self.options_thread.stop()
            self.options_thread.join(timeout=1)
            self.options_thread = None
        if getattr(self, "options_responder", None):
            self.options_responder.stop()
            self.options_responder.join(timeout=1)
            self.options_responder = None
        self.monitor_status_lbl.config(text="monitor: PARADO", style="Status.Warn.TLabel")
        self.update_button_states()

    def reset_options_monitor(self):
        self.state["options"] = {"sent": 0, "ok": 0, "other": 0, "timeout": 0, "last": "-", "rx": 0}
        self.event_q.put(("options_metrics", self.state["options"].copy()))

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

    def start_call(self):
        cfg = self.get_config()
        if not cfg:
            return
        t = threading.Thread(target=call_worker, args=(cfg, self.event_q, self.sm))
        t.daemon = True
        t.start()

    def start_load(self):
        if not self.health_ok and not self.vars["ignore_health"].get():
            messagebox.showwarning("Health", "OPTIONS fallido: no se puede iniciar generador")
            return
        cfg = self.get_config()
        if not cfg:
            return
        t = threading.Thread(target=load_worker, args=(cfg, self.event_q, self.stop_event, self.sm))
        t.daemon = True
        t.start()
        self.load_thread = t

    def toggle_uas(self):
        if getattr(self, "uas_thread", None) and self.uas_thread.is_alive():
            self.stop_event.set()
            self.uas_thread.join(timeout=1)
            self.uas_thread = None
            self.uas_btn.config(text="Iniciar UAS")
        else:
            cfg = self.get_config()
            if not cfg:
                return
            self.stop_event.clear()
            self.uas_thread = threading.Thread(
                target=uas_worker, args=(cfg, self.event_q, self.stop_event), daemon=True
            )
            self.uas_thread.start()
            self.uas_btn.config(text="Detener UAS")

    def stop_all(self):
        self.stop_event.set()
        self.stop_options_monitor()
        if getattr(self, "load_thread", None):
            self.load_thread.join(timeout=1)
            self.load_thread = None
        if getattr(self, "uas_thread", None):
            self.uas_thread.join(timeout=1)
            self.uas_thread = None
            self.uas_btn.config(text="Iniciar UAS")
        # send BYE for any pending dialogs
        self.sm.bye_all("uac")
        self.sm.bye_all("uas")
        self.update_button_states()

    def on_bye_all_uac(self):
        t = threading.Thread(target=bye_all_worker, args=(self.sm, "uac", self.event_q))
        t.daemon = True
        t.start()

    def on_bye_all_uas(self):
        t = threading.Thread(target=bye_all_worker, args=(self.sm, "uas", self.event_q))
        t.daemon = True
        t.start()

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


class OptionsResponder(threading.Thread):
    def __init__(self, bind_ip, src_port, event_q):
        super().__init__(daemon=True)
        self.bind_ip = bind_ip or "0.0.0.0"
        self.src_port = src_port
        self.event_q = event_q
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError:
                pass
        sock.bind((self.bind_ip, self.src_port))
        sock.settimeout(0.5)
        count = 0
        while not self._stop.is_set():
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            start, headers = parse_headers(data)
            if not start.startswith("OPTIONS "):
                continue
            via = headers.get("via")
            fr = headers.get("from")
            to = headers.get("to")
            call_id = headers.get("call-id")
            cseq_hdr = headers.get("cseq")
            if not all([via, fr, to, call_id, cseq_hdr]):
                continue
            if "tag=" not in to.lower():
                to = f"{to};tag=resp"
            headers_resp = {
                "Via": via,
                "From": fr,
                "To": to,
                "Call-ID": call_id,
                "CSeq": cseq_hdr,
                "Contact": f"<sip:dimitri@{sock.getsockname()[0]}:{sock.getsockname()[1]}>",
                "User-Agent": "Dimitri-4000/0.1",
                "Allow": "INVITE, ACK, CANCEL, OPTIONS, BYE",
                "Accept": "application/sdp",
            }
            sock.sendto(build_response(200, "OK", headers_resp), addr)
            count += 1
            self.event_q.put(
                (
                    "log",
                    f"Responded 200 OK to OPTIONS from {addr[0]}:{addr[1]}",
                )
            )
            self.event_q.put(("options_rx", count))
        sock.close()


class OptionsMonitorWorker(threading.Thread):
    def __init__(
        self,
        bind_ip,
        src_port,
        dst_host,
        dst_port,
        interval,
        timeout,
        cseq_start,
        reply_options_enabled,
        event_q,
    ):
        super().__init__(daemon=True)
        self.bind_ip = bind_ip
        self.src_port = src_port
        self.dst_host = dst_host
        self.dst_port = dst_port
        self.interval = interval
        self.timeout = timeout
        self.cseq = cseq_start
        self.reply_options_enabled = reply_options_enabled
        self.event_q = event_q
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def run(self):
        sm = SIPManager(protocol="udp")
        self.event_q.put(
            (
                "log",
                f"OPTIONS monitor started dst={self.dst_host}:{self.dst_port} every {self.interval}s from {self.bind_ip or '0.0.0.0'}:{self.src_port or 'ephemeral'}",
            )
        )
        counters = {"sent": 0, "ok": 0, "other": 0, "timeout": 0, "last": "-"}
        while not self._stop.is_set():
            counters["sent"] += 1
            try:
                code, _, _ = sm.send_request(
                    dst_host=self.dst_host,
                    dst_port=self.dst_port,
                    timeout=self.timeout,
                    bind_ip=self.bind_ip,
                    bind_port=self.src_port,
                    cseq=self.cseq,
                )
            except OSError as exc:
                counters["other"] += 1
                counters["last"] = "error"
                self.event_q.put(("log", f"OPTIONS error: {exc}"))
            else:
                if code is None:
                    counters["timeout"] += 1
                    counters["last"] = "timeout"
                    self.event_q.put(("log", "OPTIONS timeout"))
                elif code == 200:
                    counters["ok"] += 1
                    counters["last"] = "200"
                    self.event_q.put(("log", "OPTIONS 200"))
                else:
                    counters["other"] += 1
                    counters["last"] = str(code)
                    self.event_q.put(("log", f"OPTIONS {code}"))
            self.event_q.put(("options_metrics", counters.copy()))
            self.cseq += 1
            if self._stop.wait(self.interval):
                break
        self.event_q.put(("log", "OPTIONS monitor stopped"))

def options_worker(cfg, event_q):
    counters = {"sent": 0, "ok": 0, "other": 0, "timeout": 0}
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
                event_q.put(
                    ("log", f"Destino no escucha en {dst}:{dport}")
                )
            else:
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
        src_port_base=int(cfg.get("src_port_base", "0")),
        src_port_step=int(cfg.get("src_port_step", "10")),
        rtp_port_base=int(cfg.get("rtp_port_base", "40000")),
        rtp_port_step=int(cfg.get("rtp_port_step", "2")),
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
        rtp_stats_every=float(cfg.get("rtp_stats_every", "2.0")),
        calls=int(cfg.get("calls", "1")),
        rate=float(cfg.get("rate", "1.0")),
        max_active=int(cfg.get("max_active", "1")),
    )
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


def bye_all_worker(sm, role, event_q):
    count = sm.bye_all(role)
    event_q.put(("log", f"bye_all({role}) sent {count} BYE(s)"))


def main(args=None):
    App(args).mainloop()
