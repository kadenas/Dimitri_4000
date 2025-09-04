from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict


@dataclass
class Destination:
    ip: str
    port: int = 5060
    protocol: str = "UDP"
    interval: int = 60


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
        dests[name] = Destination(
            ip=cfg["ip"],
            port=int(cfg.get("port", 5060)),
            protocol=str(cfg.get("protocol", "UDP")).upper(),
            interval=int(cfg.get("interval", 60)),
        )
    return dests
