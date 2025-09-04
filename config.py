from __future__ import annotations

import json
import ipaddress
from dataclasses import dataclass
from pathlib import Path
from typing import Dict


@dataclass
class Destination:
    ip: str
    port: int = 5060
    protocol: str = "UDP"
    interval: int = 60
    timeout: float = 2.0
    retries: int = 3


def load_config(path: str | Path) -> Dict[str, Destination]:
    """Load destination configuration from *path*.

    The file is expected to contain a JSON or YAML mapping with a top-level
    ``destinations`` object. YAML files using only simple mappings are also
    supported as they are valid JSON.
    """
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    dests = {}
    for name, cfg in data.get("destinations", {}).items():
        ip = cfg["ip"]
        ipaddress.ip_address(ip)
        dests[name] = Destination(
            ip=ip,
            port=int(cfg.get("port", 5060)),
            protocol=str(cfg.get("protocol", "UDP")).upper(),
            interval=int(cfg.get("interval", 60)),
            timeout=float(cfg.get("timeout", 2.0)),
            retries=int(cfg.get("retries", 3)),
        )
    return dests
