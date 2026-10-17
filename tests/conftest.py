"""Shared test setup. Everything here is offline: no test touches the network, the live service
(ports 1712/1909), `output/`, `proxy-service-config.env` or the real `residential-proxies.txt`."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _load_api():
    """Proxy-api.py has a hyphen in its name, so it cannot be imported with a plain `import`."""
    if "proxy_api" in sys.modules:
        return sys.modules["proxy_api"]
    spec = importlib.util.spec_from_file_location("proxy_api", ROOT / "Proxy-api.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["proxy_api"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def api():
    return _load_api()


@pytest.fixture()
def harvester_config(tmp_path):
    """A HarvesterConfig whose files all live in tmp_path (never the project's real pool or proxy lists)."""
    from proxy_core import HarvesterConfig

    return HarvesterConfig(
        output_file=str(tmp_path / "pool.json"),
        residential_file=str(tmp_path / "residential.txt"),
        tor_file=str(tmp_path / "tor.txt"),
        country_source_codes="off",
    )
