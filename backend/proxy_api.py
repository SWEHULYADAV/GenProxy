"""
backend.proxy_api — Pythonic import alias for backend/Proxy-api.py.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_SCRIPT_PATH = Path(__file__).resolve().parent / "Proxy-api.py"

spec = importlib.util.spec_from_file_location("backend.Proxy_api", _SCRIPT_PATH)
if spec and spec.loader:
    _mod = importlib.util.module_from_spec(spec)
    sys.modules["backend.proxy_api"] = _mod
    sys.modules["proxy_api"] = _mod
    spec.loader.exec_module(_mod)

    for _k, _v in _mod.__dict__.items():
        if not _k.startswith("__"):
            globals()[_k] = _v
