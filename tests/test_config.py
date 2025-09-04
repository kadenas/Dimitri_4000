import json
from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

from config import load_config, Destination


def test_load_config_multiple_destinations(tmp_path):
    data = {
        "destinations": {
            "one": {"ip": "203.0.113.1", "port": 5070},
            "two": {"ip": "203.0.113.2", "protocol": "tcp"},
        }
    }
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps(data))

    result = load_config(cfg)
    assert set(result.keys()) == {"one", "two"}
    assert isinstance(result["one"], Destination)
    assert result["one"].port == 5070
    assert result["two"].protocol == "TCP"
