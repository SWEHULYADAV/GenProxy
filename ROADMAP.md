# Proxy Generator — Roadmap & Gap Analysis vs Premium Providers

Last updated: 2026-10-17

This compares the local service against the premium provider stack
(Bright Data, Oxylabs, Decodo, Zyte, ScraperAPI class, 2026) and lists what is
missing, what is actually worth building for a free/local project, and in what order.

## Scorecard

| Capability | Premium providers (2026) | Proxy Generator today | Gap |
|---|---|---|---|
| IP network | 100M+ residential / ISP / mobile; ~2M datacenter | free public datacenter proxies (HTTP/SOCKS4/SOCKS5) | by design (free tier) |
| Geo targeting | country / state / city / ZIP / ASN / carrier | country only (best-effort enrichment) | city + ASN missing |
| Session model | rotating + sticky, session encoded in proxy username | sticky via `session_id` (REST only, not tunnel) | tunnel sessions missing |
| Unblocking | Web Unlocker: CAPTCHA solving + JS rendering + fingerprint management, 97–99% success | block detection + rotation + humanized headers | no JS render, no CAPTCHA chain |
| Browser product | remote Scraping Browser (Playwright/Puppeteer via CDP), hosted | local `stealth_browser.py` only | no CDP endpoint |
| Search API | SERP API (Google/Bing/Yandex → JSON) | — | missing |
| Auth | zones with user:pass, IP allowlists, scoped keys | single API key + tunnel basic auth | no key ring / per-key scopes |
| Usage analytics | per-zone/key bandwidth + success dashboards, billing | in-memory tunnel counters, JSON snapshots | no persisted per-key usage |
| Target intelligence | per-domain tuning (site-specific fingerprint bundles) | per-domain memory (per target host) + global score | no site-level fingerprint bundles |
| Caching | optional scraped-response cache | — | missing |
| Rate limiting | per-key concurrency + QPS limits | global concurrency only | missing |
| Observability | metrics, structured logs, uptime/health | `/status`, `/stats`, plain logs | no metrics endpoint |
| Reliability | 98.4–99.95% success claims, SLA, pay-per-success | active-only rotation + instant runtime eviction | good for free proxies |
| AI agent integration | Bright Data MCP, Agent Browser, Agent Skills | **`proxy_mcp.py` (added 2026-10-17)** | ✅ done |
| Deployment | cloud, geo-distributed | local Windows scripts | no Docker/systemd |

## Already strong (do not regress)

- Active-only rotation with instant eviction when a real request fails
- Retry + failover across the active pool; anti-repeat of the same proxy
- Block detection (403/429/503, Cloudflare/captcha body markers)
- Scoring: success 50% + speed 25% + freshness 15% + stability 10%
- SSRF guard, API-key auth (header only), atomic JSON persistence, warmup mode
- Humanized, device-consistent browser header profiles
- Sticky sessions + per-proxy cooldowns (REST)

## Roadmap — prioritized

### P1 — highest quality jump, moderate effort

1. ~~**Per-domain proxy memory**~~ **DONE (2026-10-17)** — each `ProxyRecord`
   now keeps per-host success/failure (`domain_ok` / `domain_fail`, max 16
   hosts each, persisted in the pool JSON). `/fetch` ranks candidates for the
   target host by that memory first, so proxies that worked for a domain are
   preferred and repeat failures are skipped (sticky choice still first).
2. **Usage analytics + quotas** — per-key/per-session counters (requests, bytes,
   success, fail, avg latency) persisted in SQLite; optional daily caps.
3. **City / ASN enrichment** — switch geo enrichment to ip-api.com batch endpoint
   (100 IPs per request ~100x faster), store country + city + ASN, and expose
   `city` / `asn` filters on `/proxies`, `/next`, `/random`, `/fetch`.
4. **Response cache (TTL)** — optional short-TTL cache in `/fetch` to cut proxy
   usage and latency on repeated targets.

### P2 — product-level features

5. **`/unlock` endpoint (Web Unlocker equivalent)** — single endpoint that chains:
   API fetch → on block, retry through `stealth_browser.py` (JS rendering +
   localStorage/cookies) → captcha/challenge detection; returns HTML/JSON.
6. **Scraping-browser endpoint (CDP)** — host Playwright-driven Chromium routed
   through the tunnel and expose `ws://` CDP so clients can `connect_over_cdp`
   like a hosted Scraping Browser.
7. **Tunnel session usernames** — parse `user-<session>-country-<cc>:key@host:1912`
   style tunnel credentials for sticky + geo behavior inside the plain proxy tunnel.
8. **Key ring + rate limits** — multiple API keys with per-key concurrency/QPS caps.
9. **Metrics endpoint** — `/metrics` (Prometheus text) + optional JSON access logs.

### P3 — ops & polish

10. Simple single-page dashboard over `/status`, `/stats`, `/proxies`.
11. Dockerfile + `pyproject.toml`; systemd-friendly entrypoints.
12. IPv6 proxy support; ASN targeting; per-source health tracking for the source list.
13. pytest suite for core (parsing, scoring, pool logic, block detection) + CI.
14. README: fix stale `C:\Users\Admin\Desktop\Proxy Generator` links to the
    current folder name.

## Added on 2026-10-17

- `proxy_mcp.py` — MCP server (stdio) so any MCP host (OpenCode, Claude Desktop,
  Cursor) can operate the service:
  - service control: `proxy_service_status`, `proxy_service_start`, `proxy_service_stop`
  - inspection: `proxy_status`, `proxy_stats`, `proxy_tunnel_status`,
    `proxy_list`, `proxy_next`, `proxy_random`
  - actions: `proxy_fetch` (URL through rotating pool), `proxy_reload`
- `requirements-mcp.txt`, project `opencode.json` for one-step OpenCode setup.
- **Residential / paid proxy support**: `residential-proxies.txt` (BYO proxies with
  user:pass auth incl. SOCKS), auth preserved through verification/fetch/tunnel,
  `proxy_type` classification (residential/datacenter/mobile via ip-api) and
  `proxy_type` filters on `/proxies`, `/next`, `/random`, `/fetch` + MCP tools.
  Manual entries are never auto-pruned and are verified first each cycle.
- **Tor proxy support (free country targeting)**: bundled Tor Expert Bundle in
  `tor/` + `Tor-manager.py` — one Tor instance per country (`ExitNodes {cc}` +
  `StrictNodes 1`, own SOCKS port), parallel bootstrapping, writes
  `tor-proxies.txt`. `load_tor_proxies()` reads it every cycle (no restart),
  pins `country`, tags `proxy_type=tor`, never prunes. `--tor-file` CLI arg,
  `tor_active` in `/health`, `tor_count` in `/stats`.
- **`GET /coverage`** — country coverage vs full ISO-3166 alpha-2 list
  (covered + missing codes) for multi-country scrapers; `proxy_coverage` MCP tool.
- **`country` filter on `/fetch` and `/proxy`** (REST + `proxy_fetch` MCP tool)
  so a request can be pinned to a specific country.
- **Country-targeted source lists** — proxyscrape v4 + proxifly per-country
  templates for ~185 ISO codes by default (`--country-sources=default|off|us,de,...`).
  Fetched records are pre-tagged with the list country, so `/coverage` and
  `country=` filters fill in immediately (no waiting for geo enrichment).
- **Per-domain proxy memory** — `ProxyRecord` keeps per-host success/failure
  (`domain_ok`/`domain_fail`, pruned to 16 hosts each, persisted); `/fetch`
  ranks candidates for the target host by that memory first, so known-good
  proxies for a domain come first and known-bad ones are skipped.
- **Scheme-preserving extraction** — scheme-prefixed endpoints keep their
  protocol (`socks5h`→`socks5`, `socks4a`→`socks4`); bare `ip:port` duplicates
  of a scheme-prefixed endpoint are deduped instead of double-verified as HTTP.
- **Faster geo enrichment** — batch 25→60 per cycle (~2.4x) for quicker
  country/type classification of new proxies.
- **Browser stealth helper wired to the authenticated tunnel** — `stealth_browser.py`
  engines (Playwright / Camoufox / CloakBrowser) now:
  - inject tunnel credentials automatically from `proxy-service-config.env`
    (`PROXY_SERVICE_TUNNEL_KEY` / `PROXY_SERVICE_TUNNEL_USER`) — no flags needed
  - split proxy userinfo into `{server, username, password}` (Playwright/Camoufox
    require that shape)
  - use the Proactor event loop on Windows (Playwright needs subprocess support)
  - report per-engine errors truthfully ("all engines failed" vs "not installed")
  - live-verified through the pool: Flipkart (full ~800 KB render), Walmart,
    Instagram, TikTok and Temu render successfully
- **Bigger, faster pool defaults** — `--max-candidates` 1000→2000 and
  `--verify-batch-size` 120→250, env-overridable (`PROXY_SERVICE_MAX_CANDIDATES`
  / `PROXY_SERVICE_VERIFY_BATCH_SIZE`) and set in `proxy-service-config.env`;
  `proxy_mcp.py` forwards these tuning knobs (plus country-sources, residential
  and Tor file overrides) to the service it starts.
- **Target reality (live tests, 2026-10-17)** — light marketplaces (eBay,
  AliExpress, Alibaba, Croma, Shopsy, amazon.com) work through the free pool;
  JS-heavy stores and social homepages (Flipkart, Walmart, Instagram, TikTok,
  Temu) need the browser helper; Cloudflare/Akamai sites (Meesho, Etsy, Myntra,
  Ajio, Nykaa, Snapdeal, Facebook, Pinterest...) answer 403 to datacenter IPs
  regardless of tooling — BYO residential is the fix there.
- **Progressive pool publish** — initial verification now runs in
  `verify_batch_size` chunks and re-publishes the pool (`save_pool`) after every
  chunk, so a fresh start serves traffic within minutes instead of waiting for
  the whole `max_candidates` verification (~35 min at 2000 candidates).
- **`direct_fetch.py`** — own-IP fetch helper with a real Chrome TLS fingerprint
  (curl_cffi, added to requirements.txt). Live-verified 2026-10-17: Myntra,
  Nykaa, Flipkart (search too), JioMart, Croma, Reliance Digital, Snapdeal,
  Pinterest and Etsy India return full pages from an ordinary Indian ISP IP —
  no residential spend needed for those. Usage: `direct_fetch.py URL --output x.html`.

### Researched next steps (see RESEARCH-2026-10-17.md)

Deep research + live experiments (2026-10-17) produced this implementation
backlog, ranked by impact ÷ effort. Items 1–5 shipped the same day (see the
round-2 changelog below); item 6 is still open:

1. ~~**curl_cffi HTTP backend**~~ **DONE** — `--fetch-client curl_cffi` gives
   every pool/tunnel fetch a real Chrome TLS fingerprint (JA3/JA4).
2. ~~**Direct-route option**~~ **DONE** — `route=direct` on `/fetch`, own IP,
   rate-limited (`--direct-concurrency` / `--direct-min-interval`).
3. ~~**Unlock-API adapter**~~ **DONE** — `route=unlock` + `--unlock-url-template`
   / `--unlock-api-key` / `--unlock-hosts` (ScraperAPI/ZenRows/Scrape.do shape).
4. ~~**Akamai cookie mint→replay prototype**~~ **DONE** — `akamai_warm.py`
   (nodriver mint → `akamai-cookies.json` → curl_cffi replay).
5. ~~**nodriver as browser engine**~~ **DONE** — first in auto order for
   direct/no-proxy runs (direct-only: no proxy-auth support in Chrome CLI).
6. **free/official API examples** — Flipkart Affiliate API, Shopify Storefront
   (tokenless), Etsy Open API, eBay Browse, YouTube Data, Reddit OAuth.

## Added on 2026-10-17 (round 2 — fetch routing & stealth upgrade)

- **curl_cffi fetch backend** — `--fetch-client auto|aiohttp|curl_cffi`
  (env `PROXY_SERVICE_FETCH_CLIENT`; set to `curl_cffi` in
  `proxy-service-config.env`): pool/tunnel target fetches now send a real
  Chrome TLS fingerprint (JA3/JA4) via curl_cffi running in a 64-thread pool
  (`--curl-workers`, `--curl-impersonate chrome`). `auto` keeps aiohttp for the
  pool and curl_cffi for direct. `/stats` reports the active client.
- **`route` on `/fetch` and `/proxy`**: `auto` (unlock for `--unlock-hosts`,
  else pool) / `pool` / `direct` / `unlock`. Direct = own IP with curl_cffi,
  paced by `--direct-concurrency 2` and `--direct-min-interval 1.0`;
  `direct_calls` visible in `/stats`. Unlock = external anti-block API via
  `--unlock-url-template` (`{key}`/`{url}` places) + `--unlock-api-key` +
  `--unlock-timeout 60`; an unconfigured unlock request returns a clear 502.
- **`http_client` per request** — override the client per request
  (`aiohttp`/`curl_cffi`) without restarting the service.
- **nodriver engine** in `stealth_browser.py` — real Chrome over CDP with zero
  automation markers (best independent stealth score: 28/31 targets). Auto
  order: nodriver first when no proxy is set; skipped for proxied runs (Chrome
  CLI cannot carry proxy credentials). Chrome / Edge / Playwright-Chromium
  auto-detected (`CHROME_PATH` override), `--engine nodriver` wired into the
  CLI, engine status and install hints.
- **`akamai_warm.py`** — Akamai `_abck` cookie mint (real Chrome, own IP,
  waits for the `~-1~` validated marker) → `akamai-cookies.json` (per host:
  cookies + exact UA + timestamp) → `replay` with curl_cffi (same IP/UA/TLS).
  CLI: `mint` / `replay` / `test` / `list`; honest limits in the module
  docstring (behavioural re-challenges, expiry, IP/UA binding).
- **Case-insensitive response header lookup** (`_header_get`) — curl_cffi
  returns lower-cased header names, so text responses are now correctly
  detected as text: the REST response carries the HTML in `body` (internal
  key `body_text`; binary bodies still arrive in `body_base64`) regardless
  of which client fetched them.
- **MCP + config plumbing** — `proxy_mcp.py` forwards all new env knobs;
  `proxy-service-config.env` documents fetch/direct/unlock settings.

## Added on 2026-10-17 (round 3 — engine integration & stability fixes)

Driven by an external integration review ("should this be the engine's proxy
source?"). Verdict accepted and acted on: scoped use only — see the new
`IP-ENGINE-INTEGRATION.md` guide.

- **Tunnel country pinning** — the forward proxy now accepts usernames
  `proxy-<cc>` / `proxy-country-<cc>` (password unchanged) and routes only
  through that country: `http://proxy-sg:KEY@127.0.0.1:1909`. Empty-country
  requests fail explicitly (`502 No Proxies Available For Country XX`); CONNECT
  and plain-HTTP paths both honour the pin.
- **Residential `|CC` country tags** — `residential-proxies.txt` entries can
  carry an explicit ISO-2 country (`gate.provider.com:8080|SG`), mirroring the
  Tor file syntax. Fixes wrong-country lookup for provider gateways (geo
  lookup sees the gateway IP, not the rotating exit) and feeds `/coverage`
  directly.
- **Stability hardening (RESEARCH §2.4)** — the refresh loop is crash-isolated:
  a failing cycle logs its traceback and retries instead of freezing the pool;
  `faulthandler` + line-buffered stdout/stderr are enabled at startup so hard
  crashes leave a stack trace.
- **Secrets hygiene** — `.gitignore` excludes `proxy-service-config.env`,
  `residential-proxies.txt`, `akamai-cookies.json` and `output/`;
  `proxy-service-config.example.env` + `residential-proxies.example.txt`
  added with blank keys.
- **License/provenance note** — third-party educational project, no LICENSE
  file: keep internal, do not vendor into the engine repo (documented in
  README + integration guide).

## Reality check

Premium reliability cannot be matched with free proxies — that part is not a bug.
The realistic ceiling for this project is: **best possible selection and
routing of free proxies** (per-domain memory, smarter scoring, faster pools) and
**cloud-replacement products on top of it** (unlock endpoint, browser endpoint,
MCP/agent access). The roadmap above is ordered to maximize that ceiling.
