from __future__ import annotations

import copy
import json
import os
import socket
from pathlib import Path

from .topology import DEFAULT_TOPOLOGY


def data_dir() -> Path:
    base = os.environ.get("KVMSHARE_HOME")
    if base:
        p = Path(base)
    elif os.name == "nt":
        p = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local"))) / "KvmShare"
    else:
        p = Path.home() / ".local" / "share" / "kvmshare"
    p.mkdir(parents=True, exist_ok=True)
    return p


DEFAULTS = {
    "role": None,                      # "laptop" | "desktop" - names used in topology; set by `pair`
    "device_name": socket.gethostname(),
    "bind": "0.0.0.0",                 # connections from non-private source addresses are refused anyway
    "listen_port": 24800,
    "beacon_port": 24801,
    "pairing_port": 24802,
    "control_port": 24805,             # localhost only
    "external_input_port": 24806,      # localhost only (air-mouse adapter)
    "peer_address": None,              # optional "host[:port]" if discovery is blocked
    "features": {"input": True, "clipboard": True, "files": True},
    "topology": DEFAULT_TOPOLOGY,
    "input": {
        "hide_cursor": True,
        "entry_inset_px": 1,
        "switch_cooldown_ms": 0,
        "block_cross_while_buttons": True,
        "key_mode": "vk",              # "vk" (same character) | "scancode" (same physical key)
        "pointer_speed": 1.0,
        "forward_injected_keys": False,
        "reclaim_hotkey": "ctrl+alt+shift+f12",
        "clipboard_pause_hotkey": "ctrl+alt+shift+f11",
        "split_hotkey": "ctrl+alt+shift+f10",   # toggle: both computers fully independent <-> shared pointer
        "max_delta": 4000,
    },
    "clipboard": {
        "formats": ["text", "html", "rtf", "image"],
        "max_text_mb": 64, "max_image_mb": 32, "paused": False,
        "inline_limit_kb": 32,
    },
    "files": {
        "inbox": "%USERPROFILE%\\Downloads\\KvmShare",
        "auto_stage_max_mb": 256,      # larger offers wait for `kvmshare accept <id>`
        "require_approval": "large",   # "large" | "always" | "never"
        "max_rate_mbps": 0,            # 0 = unlimited; set to protect pointer latency on Wi-Fi
        "retries": 6,
        "max_entries": 100000,
        "max_total_gb": 500,
        "offer_ttl_s": 3600,
        "put_on_clipboard": True,
    },
    "metrics": {"stamp_moves": False},
    "log_level": "INFO",
}


def deep_merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict) and k != "topology":
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def config_path() -> Path:
    return data_dir() / "config.json"


def load_config() -> dict:
    p = config_path()
    user = {}
    if p.exists():
        user = json.loads(p.read_text(encoding="utf-8"))
    cfg = deep_merge(DEFAULTS, user)
    cfg["files"]["inbox"] = os.path.expandvars(cfg["files"]["inbox"])
    return cfg


def save_user_config(update: dict):
    p = config_path()
    cur = json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
    cur = deep_merge(cur, update)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(cur, indent=2), encoding="utf-8")
    os.replace(tmp, p)