"""Export endpoints (/proxies.txt, /export/evidence.csv, /export/evidence.json).

Entries you add yourself (residential-proxies.txt: paid providers, a SOCKS server on a consenting device) carry a
user name and password inside the proxy URL. An export is something people save, email and paste into tickets, so it
must never contain that password, and the ip / port columns must still be the host and port."""
from __future__ import annotations

import asyncio
import csv
import io

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from proxy_core import ProxyRecord

SECRET = "s3cretpass"
PLAIN = "http://203.0.113.9:8080"
AUTHENTICATED = f"socks5://brandhawk:{SECRET}@100.101.102.103:1080"


class _Service:
    def __init__(self, records):
        self.records = records

    def ranked_records(self, **kwargs):
        return list(self.records)


def _fetch(api, path, *records):
    app = web.Application()
    app["service"] = _Service(records)
    app.router.add_get("/proxies.txt", api.handle_export_txt)
    app.router.add_get("/export/evidence.csv", api.handle_export_csv)
    app.router.add_get("/export/evidence.json", api.handle_export_evidence_json)

    async def run():
        async with TestClient(TestServer(app)) as client:
            response = await client.get(path)
            return response.status, await response.text()

    return asyncio.run(run())


def _record(proxy, **fields):
    record = ProxyRecord(proxy=proxy)
    for name, value in fields.items():
        setattr(record, name, value)
    return record


def test_plain_entries_export_with_the_host_and_port_in_their_own_columns(api):
    status, body = _fetch(api, "/export/evidence.csv", _record(PLAIN, country="IN"))
    assert status == 200
    (row,) = list(csv.DictReader(io.StringIO(body)))
    assert (row["ip"], row["port"], row["protocol"], row["country"]) == ("203.0.113.9", "8080", "http", "IN")


def test_text_export_lists_host_and_port_without_the_scheme_unless_asked(api):
    _, bare = _fetch(api, "/proxies.txt", _record(PLAIN))
    _, with_scheme = _fetch(api, "/proxies.txt?with_scheme=1", _record(PLAIN))
    assert bare.strip() == "203.0.113.9:8080" and with_scheme.strip() == PLAIN


def test_json_export_is_labelled_and_counts_what_it_holds(api):
    import json

    _, body = _fetch(api, "/export/evidence.json", _record(PLAIN), _record("http://203.0.113.10:80"))
    data = json.loads(body)
    assert data["ok"] and data["total_active_proxies"] == 2 and len(data["evidence"]) == 2
    assert data["evidence"][0]["ip"] == "203.0.113.9" and data["evidence"][0]["port"] == 8080


def test_csv_export_of_an_authenticated_entry_has_the_right_columns_and_no_password(api):
    _, body = _fetch(api, "/export/evidence.csv", _record(AUTHENTICATED, country="MY", proxy_type="residential"))
    (row,) = list(csv.DictReader(io.StringIO(body)))
    assert (row["ip"], row["port"]) == ("100.101.102.103", "1080")
    assert SECRET not in body


def test_json_export_does_not_contain_the_password_of_an_authenticated_entry(api):
    _, body = _fetch(api, "/export/evidence.json", _record(AUTHENTICATED))
    assert SECRET not in body


@pytest.mark.parametrize("query", ["", "?with_scheme=1"])
def test_text_export_does_not_contain_the_password_of_an_authenticated_entry(api, query):
    _, body = _fetch(api, "/proxies.txt" + query, _record(AUTHENTICATED))
    assert SECRET not in body
