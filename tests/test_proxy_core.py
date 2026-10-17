"""proxy_core: parsing proxy lists, scoring and liveness rules, per-domain memory, BYO/Tor lists."""
from __future__ import annotations

import json
from datetime import timedelta

import pytest

from proxy_core import (
    HarvesterConfig,
    ProxyHarvester,
    ProxyRecord,
    _safe_int_map,
    extract_proxies,
    load_proxy_records,
    normalize_manual_proxy,
    normalize_proxy,
    utc_now,
)


# ---- parsing --------------------------------------------------------------------------------------
@pytest.mark.parametrize("raw, expected", [
    ("1.2.3.4:8080", "http://1.2.3.4:8080"),
    ("  1.2.3.4:80 \n", "http://1.2.3.4:80"),
    ("http://1.2.3.4:80", "http://1.2.3.4:80"),
    ("https://1.2.3.4:443", "https://1.2.3.4:443"),
    ("SOCKS5://1.2.3.4:1080", "socks5://1.2.3.4:1080"),
    ("socks5h://1.2.3.4:1080", "socks5://1.2.3.4:1080"),
    ("socks4a://1.2.3.4:1080", "socks4://1.2.3.4:1080"),
    ("user:pass@1.2.3.4:3128", "http://user:pass@1.2.3.4:3128"),
    ("socks5://u:p@1.2.3.4:1080", "socks5://u:p@1.2.3.4:1080"),
])
def test_normalize_proxy_accepts_and_canonicalises(raw, expected):
    assert normalize_proxy(raw) == expected


@pytest.mark.parametrize("raw", [
    "", "   ", "1.2.3.4", "1.2.3:80", "1.2.3.4.5:80", "256.1.1.1:80", "1.2.3.4:0", "1.2.3.4:65536",
    "1.2.3.4:abc", "example.com:80", "@1.2.3.4:80", "us er:pw@1.2.3.4:80", "-1.2.3.4:80",
])
def test_normalize_proxy_rejects_malformed_entries(raw):
    assert normalize_proxy(raw) is None


@pytest.mark.parametrize("raw, expected", [
    ("gate.provider.com:8080", "http://gate.provider.com:8080"),
    ("1.2.3.4:80", "http://1.2.3.4:80"),
    ("https://u:p@gate.x.io:33335", "http://u:p@gate.x.io:33335"),  # upstream proxies are spoken to over plain HTTP
    ("socks5://u:p@gate.x.io:1080", "socks5://u:p@gate.x.io:1080"),
])
def test_normalize_manual_proxy_accepts_hostnames_for_paid_providers(raw, expected):
    assert normalize_manual_proxy(raw) == expected


@pytest.mark.parametrize("raw", [
    "gate.x.io", "u@gate.x.io:80", "gate.x.io:99999", "gate.x.io:0", "under_score.com:80", "-bad-.com:80:x", ":80",
])
def test_normalize_manual_proxy_rejects_malformed_entries(raw):
    assert normalize_manual_proxy(raw) is None


def test_extract_proxies_reads_every_supported_shape_and_skips_garbage():
    text = "1.2.3.4:8080\nsocks5://5.6.7.8:1080\nuser:pw@9.9.9.9:3128\nnoise 999.9.9.9:80 more noise"
    found = extract_proxies(text)
    assert {"http://1.2.3.4:8080", "socks5://5.6.7.8:1080", "http://user:pw@9.9.9.9:3128"} <= found
    assert not any("999." in proxy for proxy in found)


def test_a_bare_duplicate_of_a_scheme_or_auth_endpoint_is_not_verified_twice_as_http():
    assert extract_proxies("socks5://5.6.7.8:1080\n5.6.7.8:1080") == {"socks5://5.6.7.8:1080"}
    assert extract_proxies("u:p@9.9.9.9:3128 9.9.9.9:3128") == {"http://u:p@9.9.9.9:3128"}


@pytest.mark.xfail(strict=True, reason=(
    "Known gap: lists from the internet are untrusted, yet loopback / private / link-local hosts are accepted and "
    "later probed as 'proxies' (an SSRF-style probe of the local network). Manual and Tor entries legitimately "
    "use 127.0.0.1, so the filter belongs in the free-list path only. Remove this marker when it is fixed."))
@pytest.mark.parametrize("bad", ["127.0.0.1:1712", "10.0.0.5:3128", "192.168.1.1:8080", "169.254.169.254:80", "0.0.0.0:80"])
def test_free_list_extraction_drops_non_public_hosts(bad):
    assert extract_proxies(bad) == set()


# ---- liveness and scoring ---------------------------------------------------------------------------
def _record(successes=0, failures=0, seconds=1.0, proxy="http://1.2.3.4:80"):
    record = ProxyRecord(proxy=proxy)
    for _ in range(successes):
        record.record_success(seconds, "http://probe", "1.2.3.4", 12.0)
    for _ in range(failures):
        record.record_failure("timeout", "http://probe", 12.0)
    return record


def test_scores_rank_fast_reliable_proxies_above_slow_and_failing_ones():
    fast, slow, flaky = _record(5, 0, 0.5), _record(5, 0, 9.0), _record(2, 3, 0.5)
    assert fast.score > slow.score > flaky.score > 0
    assert 0.9 < fast.score <= 1.0


def test_a_proxy_that_never_succeeded_is_never_active():
    assert not _record(0, 5).is_active(HarvesterConfig())


def test_active_rules_consecutive_failures_success_rate_slowness_and_staleness():
    config = HarvesterConfig()
    assert _record(3, 0).is_active(config)
    assert not _record(3, config.max_consecutive_failures).is_active(config)

    # F S F F: only 2 failures in a row, but 1 success in 4 checks (25%) is under the 35% floor
    low_rate = _record(0, 0)
    low_rate.record_failure("e", "u", 12.0)
    low_rate.record_success(1.0, "u", "o", 12.0)
    low_rate.record_failure("e", "u", 12.0)
    low_rate.record_failure("e", "u", 12.0)
    assert not low_rate.is_active(config)

    assert not _record(3, 0, seconds=config.max_response_time + 1).is_active(config)

    stale = _record(3, 0)
    stale.last_seen_success = utc_now() - timedelta(seconds=config.stale_after_seconds + 60)
    assert not stale.is_active(config)


def test_only_the_last_twenty_response_times_are_kept():
    assert len(_record(30, 0).response_times) == 20


def test_a_record_survives_a_json_round_trip_with_its_tags_and_memory():
    record = _record(4, 1)
    record.country, record.proxy_type, record.manual = "SG", "residential", True
    record.note_domain_result("lazada.sg", True)
    restored = ProxyRecord.from_dict(json.loads(json.dumps(record.to_dict())))
    assert (restored.proxy, restored.country, restored.proxy_type, restored.manual) == (
        record.proxy, "SG", "residential", True)
    assert restored.domain_ok == {"lazada.sg": 1}
    assert restored.protocol == "http" and abs(restored.score - record.score) < 0.01


def test_malformed_domain_memory_in_a_saved_pool_is_ignored_not_fatal():
    assert _safe_int_map({"a.com": 3, "b.com": "x", "c.com": None}) == {"a.com": 3}
    assert _safe_int_map("not a dict") == {} and _safe_int_map(None) == {}


# ---- per-domain memory ------------------------------------------------------------------------------
def test_domain_memory_counts_per_host_case_insensitively_and_ignores_empty_hosts():
    record = ProxyRecord(proxy="http://1.2.3.4:80")
    record.note_domain_result("Shop.Example", True)
    record.note_domain_result("shop.example", True)
    record.note_domain_result("shop.example", False)
    record.note_domain_result("", True)
    assert record.domain_net("SHOP.EXAMPLE") == 1 and record.domain_net("other.example") == 0
    assert record.domain_ok == {"shop.example": 2} and "" not in record.domain_ok


def test_domain_memory_is_capped_and_keeps_the_hosts_it_saw_most():
    record = ProxyRecord(proxy="http://1.2.3.4:80")
    for _ in range(10):
        record.note_domain_result("busy.example", True)
    for index in range(40):
        record.note_domain_result(f"host{index}.example", False)
    assert len(set(record.domain_ok) | set(record.domain_fail)) <= ProxyRecord._MAX_DOMAIN_KEYS
    assert record.domain_ok.get("busy.example") == 10


# ---- pool ranking, filters, persistence ---------------------------------------------------------------
def _harvester(config, records):
    harvester = ProxyHarvester(config, sources=["http://lists.invalid/x.txt"])
    harvester.records = {record.proxy: record for record in records}
    harvester.active_proxies = set(harvester.records)
    return harvester


def test_ranking_orders_by_score_and_filters_by_country_protocol_and_score(harvester_config):
    best = _record(5, 0, 0.5, "http://1.1.1.1:80")
    best.country = "SG"
    mid = _record(5, 0, 8.0, "socks5://2.2.2.2:1080")
    mid.country = "SG"
    weak = _record(2, 3, 0.5, "http://3.3.3.3:80")
    weak.country = "DE"
    harvester = _harvester(harvester_config, [weak, best, mid])
    assert [r.proxy for r in harvester.ranked_active_records()] == [best.proxy, mid.proxy, weak.proxy]
    assert harvester.best_proxy().proxy == best.proxy
    assert [r.proxy for r in harvester._filtered_records(country="sg")] == [best.proxy, mid.proxy]
    assert [r.proxy for r in harvester._filtered_records(protocol="SOCKS5")] == [mid.proxy]
    assert [r.proxy for r in harvester._filtered_records(min_score=best.score)] == [best.proxy]


def test_an_empty_pool_has_no_best_proxy(harvester_config):
    assert _harvester(harvester_config, []).best_proxy() is None


def test_load_proxy_records_handles_missing_file_both_payload_shapes_and_bad_items(tmp_path):
    assert load_proxy_records(tmp_path / "nope.json") == {}
    good = _record(2, 0, proxy="http://1.1.1.1:80").to_dict()
    (tmp_path / "wrapped.json").write_text(json.dumps({"proxies": [good, {"no_proxy_key": 1}]}), encoding="utf-8")
    (tmp_path / "bare.json").write_text(json.dumps([good]), encoding="utf-8")
    assert list(load_proxy_records(tmp_path / "wrapped.json")) == ["http://1.1.1.1:80"]
    assert list(load_proxy_records(tmp_path / "bare.json")) == ["http://1.1.1.1:80"]


# ---- BYO residential and Tor lists --------------------------------------------------------------------
def test_residential_file_tags_country_comments_hostnames_and_multiple_entries(harvester_config, tmp_path):
    (tmp_path / "residential.txt").write_text(
        "# my paid proxies\n"
        "gate.provider.com:8080|SG   # gateway, exit country cannot be guessed\n"
        "user:pw@1.2.3.4:3128, socks5://u:p@5.6.7.8:1080\n"
        "not a proxy\n"
        "gate.other.com:9000|ZZZ\n",
        encoding="utf-8")
    harvester = ProxyHarvester(harvester_config, sources=[])
    entries = harvester.load_manual_proxies()
    assert set(entries) == {"http://gate.provider.com:8080", "http://user:pw@1.2.3.4:3128",
                            "socks5://u:p@5.6.7.8:1080", "http://gate.other.com:9000"}
    gateway = harvester.records["http://gate.provider.com:8080"]
    assert (gateway.country, gateway.proxy_type, gateway.manual) == ("SG", "residential", True)
    assert harvester.records["http://gate.other.com:9000"].country == "", "a 3-letter tag is not an ISO-2 country"


def test_residential_file_does_not_overwrite_an_existing_type_and_a_missing_file_is_fine(harvester_config, tmp_path):
    harvester = ProxyHarvester(harvester_config, sources=[])
    assert harvester.load_manual_proxies() == {}
    existing = ProxyRecord(proxy="http://gate.x.io:80", proxy_type="mobile")
    harvester.records[existing.proxy] = existing
    (tmp_path / "residential.txt").write_text("gate.x.io:80\n", encoding="utf-8")
    harvester.load_manual_proxies()
    assert existing.proxy_type == "mobile" and existing.manual


def test_tor_file_pins_country_and_marks_entries_as_tor(harvester_config, tmp_path):
    (tmp_path / "tor.txt").write_text("# generated\nsocks5://127.0.0.1:9701|us\nsocks5://127.0.0.1:9702|de\nbroken\n",
                                      encoding="utf-8")
    harvester = ProxyHarvester(harvester_config, sources=[])
    assert len(harvester.load_tor_proxies()) == 2
    record = harvester.records["socks5://127.0.0.1:9701"]
    assert (record.country, record.proxy_type, record.manual) == ("US", "tor", True)


# ---- country-targeted source lists ----------------------------------------------------------------------
@pytest.mark.parametrize("setting", ["off", "none", "0", "", "disabled"])
def test_country_sources_can_be_switched_off(setting):
    harvester = ProxyHarvester(HarvesterConfig(country_source_codes=setting), sources=["http://a.invalid/x"])
    assert harvester.sources == ["http://a.invalid/x"] and harvester.source_country == {}


def test_country_sources_for_listed_codes_skip_invalid_ones_and_tag_every_url():
    harvester = ProxyHarvester(HarvesterConfig(country_source_codes="sg, de;XYZ 7a"), sources=[])
    assert set(harvester.source_country.values()) == {"SG", "DE"}
    assert all(url in harvester.sources for url in harvester.source_country)


def test_default_country_sources_cover_many_countries():
    harvester = ProxyHarvester(HarvesterConfig(country_source_codes="default"), sources=[])
    assert len(set(harvester.source_country.values())) > 100


def test_the_free_residential_recipe_line_loads_as_a_pinned_residential_exit(harvester_config, tmp_path):
    """FREE-RESIDENTIAL.md section 2: a SOCKS5 server on a consenting device, reached over Tailscale (100.64.0.0/10)."""
    line = "socks5://brandhawk:long-pass@100.101.102.103:1080"
    (tmp_path / "residential.txt").write_text(f"{line}|MY\n", encoding="utf-8")
    harvester = ProxyHarvester(harvester_config, sources=[])
    assert list(harvester.load_manual_proxies()) == [line]
    record = harvester.records[line]
    assert (record.country, record.proxy_type, record.manual, record.protocol) == ("MY", "residential", True, "socks5")


def test_evaluate_anonymity():
    from proxy_core import _evaluate_anonymity
    assert _evaluate_anonymity({"headers": {"x-forwarded-for": "1.2.3.4"}}) == "transparent"
    assert _evaluate_anonymity({"headers": {"via": "1.1 squid"}}) == "anonymous"
    assert _evaluate_anonymity({"headers": {"user-agent": "Mozilla/5.0"}}) == "elite"
    assert _evaluate_anonymity({"via": "1.1 tinyproxy"}) == "anonymous"
    assert _evaluate_anonymity({"forwarded": "for=1.2.3.4"}) == "transparent"

