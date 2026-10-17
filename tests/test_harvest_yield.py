"""Harvest yield: what decides how many working proxies a cycle finds.

Free lists hold hundreds of thousands of entries but a cycle verifies only max_candidates of them, so the
pool depends on reading every list correctly (SOCKS lists, JSON APIs), spending the budget on entries that
were not just seen dead, and never keeping a proxy under the wrong protocol. All offline."""
from __future__ import annotations

import asyncio
import json
import time

import aiohttp
import pytest

import proxy_core
from proxy_core import (
    DEFAULT_SOURCES,
    HarvesterConfig,
    ProbeOutcome,
    ProxyHarvester,
    ProxyRecord,
    _classify_proxy_type,
    _extract_origin,
    _origin_is_public,
    extract_proxies,
    extract_proxies_with_hints,
    load_sources_file,
    previous_session_pool,
    probe_proxy,
    source_protocol_hint,
    tcp_preflight_check,
)


# ---- reading lists ------------------------------------------------------------------------------------
@pytest.mark.parametrize("url, expected", [
    ("https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt", "socks5"),
    ("https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt", "socks5"),
    ("https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4_RAW.txt", "socks4"),
    ("https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=socks4", "socks4"),
    ("https://api.proxyscrape.com/v2/?request=get&protocol=http&timeout=5000", "http"),
    ("https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt", "http"),
    ("https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.txt", "http"),
])
def test_the_list_url_tells_which_protocol_its_bare_entries_speak(url, expected):
    assert source_protocol_hint(url) == expected


def test_bare_entries_of_a_socks_list_are_tested_as_socks_and_explicit_schemes_win():
    body = "8.8.4.4:1080\nhttp://8.8.8.8:3128\n"
    assert extract_proxies(body, "socks5") == {"socks5://8.8.4.4:1080", "http://8.8.8.8:3128"}
    assert extract_proxies(body) == {"http://8.8.4.4:1080", "http://8.8.8.8:3128"}, "default stays http"


def test_json_apis_with_separate_ip_and_port_fields_are_read_with_their_protocols_and_country():
    body = json.dumps({"data": [
        {"ip": "79.172.212.71", "port": "1080", "protocols": ["socks5"], "country": "HU"},
        {"ip": "8.8.8.8", "port": 8080, "protocols": ["http", "https"], "country": "US"},
        {"ip": "1.1.1.1", "port": "3128"},
        {"ip": "10.0.0.1", "port": "80"},
    ], "total": 4})
    assert extract_proxies_with_hints(body) == {
        "socks5://79.172.212.71:1080": "HU",
        "http://8.8.8.8:8080": "US",
        "http://1.1.1.1:3128": "",
    }


def _sources_py(path, sources, templates=()):
    path.write_text(f"SOURCES = {list(sources)!r}\nCOUNTRY_SOURCE_TEMPLATES = {list(templates)!r}\n",
                    encoding="utf-8")
    return path


def test_sources_file_dedupes_drops_non_urls_and_files_templates_by_their_placeholder(tmp_path):
    path = _sources_py(tmp_path / "proxy_sources.py", [
        "https://a.example/http.txt", "  https://b.example/socks5.txt ", "https://a.example/http.txt",
        "not a url", 42, "https://c.example/{CC}/data.txt",
    ], ["https://d.example/?country={cc}"])
    assert load_sources_file(path) == (
        ["https://a.example/http.txt", "https://b.example/socks5.txt"],
        ["https://c.example/{CC}/data.txt", "https://d.example/?country={cc}"],
    )


def test_a_broken_or_missing_sources_file_reads_as_empty_instead_of_crashing(tmp_path):
    broken = tmp_path / "proxy_sources.py"
    broken.write_text('SOURCES = [\n    "https://a.example/http.txt"\n    "oops missing bracket"\n', encoding="utf-8")
    assert load_sources_file(broken) == ([], [])
    assert load_sources_file(tmp_path / "nope.py") == ([], [])


def test_the_shipped_sources_file_loads_lists_and_country_templates():
    assert proxy_core.default_sources_path().name == "proxy_sources.py"
    assert proxy_core.default_sources_path().parent.name == "backend"
    assert len(DEFAULT_SOURCES) > 50
    assert proxy_core.COUNTRY_SOURCE_TEMPLATES and all(
        "{cc}" in t or "{CC}" in t for t in proxy_core.COUNTRY_SOURCE_TEMPLATES)


def test_an_edited_sources_file_is_picked_up_and_extra_lists_are_kept(tmp_path):
    sources_file = _sources_py(tmp_path / "proxy_sources.py", ["https://one.example/http.txt"])
    harvester = ProxyHarvester(
        HarvesterConfig(country_source_codes="off"),
        sources=[DEFAULT_SOURCES[0], "https://extra.example/mine.txt"],
    )
    harvester._sources_path = sources_file
    harvester._sources_mtime = None
    harvester._maybe_reload_sources_file()
    assert harvester.sources == ["https://one.example/http.txt", "https://extra.example/mine.txt"]

    for bad_edit in ("SOURCES = []\n", "SOURCES = [\n"):
        sources_file.write_text(bad_edit, encoding="utf-8")
        harvester._sources_mtime = None
        harvester._maybe_reload_sources_file()
        assert harvester.sources == ["https://one.example/http.txt", "https://extra.example/mine.txt"], (
            "an empty or broken edit must not wipe the lists")


def test_a_harvester_on_its_own_lists_does_not_track_the_sources_file():
    assert ProxyHarvester(HarvesterConfig(), sources=["http://lists.invalid/x.txt"])._sources_path is None


# ---- telling a working proxy from a broken one ------------------------------------------------------
def test_an_origin_comes_from_an_ip_echo_not_from_a_portal_page_that_mentions_an_ip():
    assert _extract_origin('{"ip": "8.8.8.8"}') == "8.8.8.8"
    assert _extract_origin("8.8.8.8\n") == "8.8.8.8"
    portal = "<html><body>Router login. Gateway 192.168.1.1 - please sign in" + " " * 80 + "</body></html>"
    assert _extract_origin(portal) == ""
    assert _origin_is_public("8.8.8.8, 1.1.1.1") and not _origin_is_public("192.168.1.1")


@pytest.mark.parametrize("geo, expected", [
    ({"hosting": False, "isp": "Real Time Data Services Private Limited", "as": "AS18229 CtrlS"}, "datacenter"),
    ({"hosting": False, "isp": "Zenlayer Inc", "as": "AS62610 Zenlayer Inc"}, "datacenter"),
    ({"hosting": False, "isp": "Cogento Backbone Limited"}, "datacenter"),
    ({"hosting": False, "isp": '"Domain names registrar REG.RU", Ltd'}, "datacenter"),
    ({"hosting": False, "isp": "Shijiazhuang IDC network, CHINANET Hebei"}, "datacenter"),
    ({"hosting": False, "isp": "GLB Bulut Teknolojisi Limited Sirketi"}, "datacenter"),
    ({"hosting": False, "isp": "Midcontinent Communications", "as": "AS11232 Midco"}, "residential"),
    ({"hosting": False, "isp": "PT. Telekomunikasi Indonesia"}, "residential"),
    ({"hosting": True, "isp": "Anything"}, "datacenter"),
    ({"hosting": False, "isp": "Bharti Airtel Ltd.", "as": "AS24560 Bharti Airtel"}, "residential"),
    ({"hosting": False, "isp": "Google Fiber Inc."}, "residential"),
    ({"hosting": False, "isp": "Colombia Telecomunicaciones"}, "residential"),
    ({"mobile": True, "isp": "Reliance Jio"}, "mobile"),
])
def test_hosting_networks_that_ip_api_does_not_flag_are_not_labelled_residential(geo, expected):
    assert _classify_proxy_type(geo) == expected


def test_preflight_still_dials_provider_hostnames_but_never_private_ips(monkeypatch):
    dialed = []

    class _Writer:
        def close(self):
            pass

        async def wait_closed(self):
            pass

    async def fake_open_connection(host, port):
        dialed.append(host)
        return None, _Writer()

    monkeypatch.setattr(proxy_core.asyncio, "open_connection", fake_open_connection)
    assert asyncio.run(tcp_preflight_check("gate.provider.com", 8080)) is True
    assert asyncio.run(tcp_preflight_check("10.0.0.5", 3128)) is False
    assert dialed == ["gate.provider.com"]


class _RaisingSession:
    def __init__(self, exc):
        self.exc = exc
        self.urls = []

    def get(self, url, **kwargs):
        self.urls.append(url)
        raise self.exc


def _probe(monkeypatch, exc):
    socks_tries = []

    async def fake_preflight(host, port, timeout=1.8):
        return True

    async def fake_socks(proxy, proxy_url, test_urls, timeout_seconds, user_agent):
        socks_tries.append(proxy_url)
        return ProbeOutcome(proxy=proxy, working=False, error="refused")

    monkeypatch.setattr(proxy_core, "tcp_preflight_check", fake_preflight)
    monkeypatch.setattr(proxy_core, "_probe_socks_proxy", fake_socks)
    session = _RaisingSession(exc)
    urls = ["https://a.example/ip", "https://b.example/ip", "https://c.example/ip"]
    outcome = asyncio.run(probe_proxy(session, "http://8.8.8.8:3128", urls, 5.0))
    return outcome, session.urls, socks_tries


def test_a_timeout_ends_the_probe_at_once_without_trying_more_urls_or_socks(monkeypatch):
    outcome, urls, socks_tries = _probe(monkeypatch, asyncio.TimeoutError())
    assert not outcome.working and outcome.timed_out
    assert len(urls) == 1 and socks_tries == []


def test_a_proxy_that_answered_in_http_is_not_retried_as_socks(monkeypatch):
    outcome, urls, socks_tries = _probe(monkeypatch, aiohttp.ClientHttpProxyError(None, (), status=403))
    assert not outcome.working and len(urls) == 3 and socks_tries == []


def test_an_endpoint_that_drops_http_is_tried_as_socks5_then_socks4(monkeypatch):
    _, _, socks_tries = _probe(monkeypatch, aiohttp.ServerDisconnectedError())
    assert socks_tries == ["socks5://8.8.8.8:3128", "socks4://8.8.8.8:3128"]


# ---- spending the verification budget -----------------------------------------------------------------
def _offline_harvester(config, lists):
    """A harvester whose list downloads return *lists* ({url: {proxy: country}}) instead of fetching."""
    harvester = ProxyHarvester(config, sources=list(lists))

    async def fake_fetch(url, retries=2):
        return dict(lists[url])

    harvester._fetch_source = fake_fetch
    return harvester


def test_candidates_that_just_failed_wait_out_their_backoff_and_free_the_budget(harvester_config):
    harvester_config.max_candidates = 2
    lists = {"https://l.example/http.txt": {f"http://8.8.8.{i}:80": "" for i in range(1, 5)}}
    harvester = _offline_harvester(harvester_config, lists)
    first = asyncio.run(harvester.collect_candidates())
    assert len(first) == 2
    for proxy in first:
        record = harvester.records[proxy]
        record.record_failure("timeout", "u", 12.0)
        harvester._schedule_retry(record)
    second = asyncio.run(harvester.collect_candidates())
    assert set(second).isdisjoint(first), "the next cycle checks entries it has not just seen fail"
    assert harvester.last_collect_stats == {"unique_candidates": 4, "cooling_down": 2, "queued": 2}


def test_retry_backoff_doubles_per_failure_and_is_capped(harvester_config):
    harvester = ProxyHarvester(harvester_config, sources=[])
    record = ProxyRecord(proxy="http://8.8.8.8:80")
    delays = []
    for _ in range(8):
        record.record_failure("timeout", "u", 12.0)
        harvester._schedule_retry(record)
        delays.append(round(harvester._cooldown[record.proxy][0] - time.time()))
    base = harvester_config.retry_backoff_seconds
    assert delays[:3] == [pytest.approx(base, abs=2), pytest.approx(2 * base, abs=2), pytest.approx(4 * base, abs=2)]
    assert max(delays) <= harvester_config.max_retry_backoff_seconds


def test_a_proven_proxy_having_a_bad_moment_is_not_put_on_backoff(harvester_config):
    harvester = ProxyHarvester(harvester_config, sources=[])
    record = ProxyRecord(proxy="http://8.8.8.8:80")
    record.record_success(0.5, "u", "8.8.8.8", 12.0)
    record.record_failure("timeout", "u", 12.0)
    harvester._schedule_retry(record)
    assert record.proxy not in harvester._cooldown


def test_entries_from_lists_with_a_better_hit_rate_are_verified_first(harvester_config):
    harvester_config.max_candidates = 1
    good, bad = "https://good.example/http.txt", "https://bad.example/http.txt"
    harvester = _offline_harvester(harvester_config, {good: {"http://8.8.8.1:80": ""},
                                                       bad: {"http://8.8.8.2:80": ""}})
    harvester.source_tested.update({good: 100, bad: 100})
    harvester.source_working.update({good: 40, bad: 1})
    assert list(asyncio.run(harvester.collect_candidates())) == ["http://8.8.8.1:80"]


def test_country_hints_from_json_lists_tag_new_records(harvester_config):
    harvester = _offline_harvester(harvester_config, {"https://geo.example/api": {"http://8.8.8.8:80": "SG"}})
    asyncio.run(harvester.collect_candidates())
    assert harvester.records["http://8.8.8.8:80"].country == "SG"


# ---- verification bookkeeping -------------------------------------------------------------------------
def _verify_with(monkeypatch, harvester, outcome_for):
    async def fake_probe(session, proxy, test_urls, timeout_seconds, user_agent=""):
        return outcome_for(proxy)

    monkeypatch.setattr(proxy_core, "probe_proxy", fake_probe)
    harvester.session = object()
    return asyncio.run(harvester.verify_proxies(list(harvester.records)))


def test_a_socks_server_listed_as_http_is_kept_as_socks_and_the_http_entry_is_retired(monkeypatch, harvester_config):
    harvester = ProxyHarvester(harvester_config, sources=[])
    listed = ProxyRecord(proxy="http://8.8.8.8:1080", source_urls=["https://l.example/all.txt"], country="DE")
    harvester.records[listed.proxy] = listed
    _verify_with(monkeypatch, harvester, lambda proxy: ProbeOutcome(
        proxy="socks5://8.8.8.8:1080", working=True, response_time=0.4, origin="8.8.8.8"))
    assert harvester.active_proxies == {"socks5://8.8.8.8:1080"}
    detected = harvester.records["socks5://8.8.8.8:1080"]
    assert detected.country == "DE" and detected.source_urls == ["https://l.example/all.txt"]
    assert not listed.is_active(harvester.config) and harvester._cooling_down(listed.proxy, time.time())


def test_first_checks_feed_the_per_list_hit_rate(monkeypatch, harvester_config):
    harvester = ProxyHarvester(harvester_config, sources=[])
    for i, url in ((1, "https://l.example/a.txt"), (2, "https://l.example/a.txt"), (3, "https://l.example/b.txt")):
        harvester.records[f"http://8.8.8.{i}:80"] = ProxyRecord(proxy=f"http://8.8.8.{i}:80", source_urls=[url])
    _verify_with(monkeypatch, harvester, lambda proxy: ProbeOutcome(
        proxy=proxy, working=proxy.endswith(".1:80"), response_time=0.4, origin="8.8.8.8"))
    assert harvester.source_tested == {"https://l.example/a.txt": 2, "https://l.example/b.txt": 1}
    assert harvester.source_working == {"https://l.example/a.txt": 1}


# ---- warm start -----------------------------------------------------------------------------------------
def test_a_new_session_seeds_from_the_previous_sessions_pool(tmp_path):
    previous = tmp_path / "api_old"
    previous.mkdir()
    (previous / "active_proxies.json").write_text("{}", encoding="utf-8")
    marker = tmp_path / "latest_api_session.txt"
    assert previous_session_pool(marker, "active_proxies.json") == "", "no marker yet"
    marker.write_text(str(previous), encoding="utf-8")
    assert previous_session_pool(marker, "output/active_proxies.json") == str(previous / "active_proxies.json")


def test_seeded_records_and_list_stats_are_restored_and_free_proxies_are_reclassified(tmp_path):
    working = ProxyRecord(proxy="http://8.8.8.8:80", proxy_type="residential", country="IN")
    working.record_success(0.5, "u", "8.8.8.8", 12.0)
    paid = ProxyRecord(proxy="http://u:p@gate.example.com:80", proxy_type="residential", manual=True)
    seed = tmp_path / "seed.json"
    seed.write_text(json.dumps({
        "proxies": [working.to_dict(), paid.to_dict()],
        "sources": [{"url": "https://l.example/a.txt", "tested": 50, "working": 9}],
    }), encoding="utf-8")
    config = HarvesterConfig(output_file=str(tmp_path / "new.json"), seed_file=str(seed),
                             residential_file=str(tmp_path / "r.txt"), tor_file=str(tmp_path / "t.txt"),
                             country_source_codes="off")

    async def enter():
        async with ProxyHarvester(config, sources=[]) as harvester:
            return harvester

    harvester = asyncio.run(enter())
    assert "http://8.8.8.8:80" in harvester.active_proxies
    assert harvester.records["http://8.8.8.8:80"].proxy_type == "", "free proxies get labelled again"
    assert harvester.records["http://8.8.8.8:80"].country == "IN"
    assert harvester.records[paid.proxy].proxy_type == "residential"
    assert (harvester.source_tested, harvester.source_working) == (
        {"https://l.example/a.txt": 50}, {"https://l.example/a.txt": 9})
