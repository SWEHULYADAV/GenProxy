# Engine Integration Guide — Proxy Generator as a scoped proxy source

Last updated: 2026-10-17. Companion docs: `ROADMAP.md` (what is and is not built).

This page answers the review that said this folder "should not be the main
proxy source" for the engine. **The review is right about the global-proxy
part** — and this guide shows the scoped setup that does work, plus the code
changes made on 2026-10-17 to support it.

## TL;DR

- **Never set this service as the engine's global `IP_ENGINE_PROXY_URL`.**
  Authenticated API calls (eBay Browse, Etsy, Walmart Affiliate, anything with
  keys/tokens) must NOT travel through rotating free proxies.
- Use it as a **scoped route source**: only for public, non-authenticated
  reads where a rotating datacenter exit is acceptable.
- For bot-walled or country-locked markets use, in this order of preference:
  official API → own IP (direct route) → paid country residential (pinned) →
  unlock API → free pool (last).

## Objection → answer (what was fixed on 2026-10-17)

| Objection from the review | Status |
|---|---|
| Free datacenter IPs are blocked by Akamai/DataDome/AWS WAF | **True, accepted.** Those hosts are NOT free-pool use cases — see the matrix. Options for them: direct (own IP), country residential, unlock API, official API. |
| Pool is weak: 30–250 active from ~2000 candidates | **True, documented honestly.** Free pool = volatile by nature. `/stats`, `/coverage` expose live reality. A broken refresh cycle could previously freeze the pool silently — **fixed** (refresh loop now survives bad cycles, logs tracebacks, keeps retrying). |
| A service run died with no traceback (RESEARCH §2.4) | **Addressed:** `faulthandler` + line-buffered stdout/stderr are now enabled at startup, and the refresh loop never lets one bad cycle kill the process. Start commands should run with `-u` (see below). |
| Country-matched IPs needed for Lazada x6 / Printerval / Walmart MX/CL | **Fixed:** the tunnel now supports **country pinning via username**: `http://proxy-sg:KEY@127.0.0.1:1909` (or `proxy-country-sg`). `residential-proxies.txt` now supports an explicit `|CC` country tag for provider gateway hostnames. Missing-country requests fail with an explicit `502 No Proxies Available For Country XX` instead of silently using the wrong country. |
| Wrong "Down" verdicts from proxy timeouts/403s | **Product-side caution:** a timeout through a free proxy is not evidence a target is down. Use the target's API or the direct route for status checks; never build user-visible evidence from rotating unknown IPs. The service now returns explicit errors (`no active proxies`, `country=...`) you can classify instead of treating as "down". |
| License: third-party project, no LICENSE file, disclaimer says educational/personal use | **Handled:** see "License & provenance". Keep it internal; do not commit it into the engine repo. |
| Keys in plaintext in `proxy-service-config.env` | **Handled:** `.gitignore` now excludes the config, residential file and cookie cache; `proxy-service-config.example.env` ships with blank keys. Never copy the real config anywhere. |

## Honest capability matrix (measured 2026-10-17, India ISP line)

| Target class | Examples | Free pool (this service) | Own IP via `route=direct` | Country residential (yours, pinned) | Official API |
|---|---|---|---|---|---|
| No bot protection | most blogs, gov, small shops | ✅ works | ✅ best | overkill | — |
| Cloudflare (soft) | many small shops | ⚠️ mixed | ✅ | ✅ | — |
| Akamai sensor | Myntra, Nykaa, JioMart, Pinterest | ❌ 403 (dead end) | ✅ full pages (curl_cffi, Chrome TLS) | ✅ | — |
| Akamai sensor + strict (Ajio) | Ajio | ❌ HTML shell | ✅ SPA JSON APIs (`/api/search`, `/api/p/<code>`); `/p/<code>` HTML also via pool; headful mint passes (headless = Access Denied) | ✅ | — |
| Akamai sensor + strict (Meesho) | Meesho | ❌ HTML shell | ✅ `POST /api/v1/products/search` JSON (direct); product pages 403 → nodriver | ✅ | — |
| DataDome | Etsy (US locale) | ❌ | ⚠️ sometimes | ✅ | ✅ Etsy Open API (free keys) |
| AWS WAF | Amazon product pages | ❌ 202 | ⚠️ | ✅ | ✅ eBay Browse / Amazon PA-API |
| Walmart US | walmart.com | ❌ | ❌ | ✅ | ✅ Walmart Affiliate (free keys) |
| Lazada (SG/MY/TH/VN/ID/PH) | lazada.\* | ❌ + CAPTCHA | ❌ | ✅ (CAPTCHA stays — we do not solve CAPTCHAs) | — |
| Measured pool scale | — | ~30–250 active of ~2000 candidates (5–15%), re-verified every cycle | rate-limited: 2 concurrent, 1 req/s | depends on your plan | — |

## Integration recipes

### 1) Scoped routes — the recommended baseline

Engine-side mapping (adapt to your engine's route schema; the value is the
proxy URL this service exposes):

| Host pattern (example) | Proxy URL | Notes |
|---|---|---|
| public/simple targets only | `http://proxy:KEY@127.0.0.1:1909` | any-country rotation |
| `*.lazada.sg` | `http://proxy-sg:KEY@127.0.0.1:1909` | SG exit; needs SG coverage (see below) |
| `*.lazada.com.my` | `http://proxy-my:KEY@127.0.0.1:1909` | MY exit |
| `*.walmart.com.mx` | `http://proxy-mx:KEY@127.0.0.1:1909` | MX exit |
| Myntra/Nykaa pages | *(no proxy)* call `POST /fetch {"route":"direct"}` | own IP wins there |
| Etsy/eBay/Walmart US | *(no proxy)* official APIs | keys, not proxies |

`proxy-sg` etc. only work when the pool actually contains SG exits. Check
`GET /coverage` (127.0.0.1:1712, header `X-API-Key`) — or add SG residential
entries (recipe 3). Empty-country requests now return
`502 No Proxies Available For Country SG` so the engine can fail honestly.

### 2) Own IP — `route=direct` (India stores, biggest zero-cost win)

```bat
curl.exe -X POST http://127.0.0.1:1712/fetch -H "X-API-Key: KEY" -H "Content-Type: application/json" ^
  -d "{\"url\":\"https://www.myntra.com/shoes\",\"route\":\"direct\"}"
```

- Full pages on Myntra / Nykaa / Flipkart / JioMart / Croma / Snapdeal /
  Pinterest via curl_cffi + Chrome TLS.
- Server-side pacing: 2 concurrent, 1 request/second (`direct_calls` in
  `/stats`) — do not disable it.
- Standalone equivalent: `venv\Scripts\python direct_fetch.py URL`.

### 3) Paid country residential — the only real fix for country-locked markets

Add provider entries to `residential-proxies.txt` with the `|CC` tag:

```
gate.provider.com:8080|SG
http://user:pass@gate.provider.com:8081|MY
socks5://user:pass@gw.provider.com:32325|MX
```

Then the engine uses `http://proxy-sg:KEY@127.0.0.1:1909` exactly as above —
one tunnel, per-route countries, no engine changes beyond the proxy URL.
These entries are never auto-pruned and are re-verified each cycle.

### 4) Unlock API for occasional hard pages (free tiers stack to ~6K/mo)

`proxy-service-config.env`:

```
PROXY_SERVICE_UNLOCK_URL_TEMPLATE=http://api.scraperapi.com?api_key={key}&url={url}
PROXY_SERVICE_UNLOCK_API_KEY=...
PROXY_SERVICE_UNLOCK_HOSTS=meesho.com,etsy.com
```

Then `/fetch` with `route=unlock` (or hosts in `--unlock-hosts` auto-route).
Free tiers: Bright Data Web Unlocker 5K/mo, ZenRows 5K/mo, Scrape.do 1K/mo.

### 5) Official APIs (agree with the review — do these first)

Etsy Open API, eBay Browse, Walmart Affiliate: free keys and they beat every
proxy for the US markets. This service coexists; it does not replace them.

### 6) Ajio / Meesho — the SPA-API jugaad (found 2026-10-17)

Both sites block their HTML shells, but their own front-ends call plain JSON
APIs on the same hosts — those are far weaker:

- **Ajio listings**: `GET https://www.ajio.com/api/search?fields=SITE&currentPage=0&pageSize=45&format=json&query=shoes`
  — works direct **and through the free pool** (verified 200 + full JSON).
- **Ajio product**: `GET https://www.ajio.com/api/p/{code}` (JSON) or
  `GET https://www.ajio.com/p/{code}` (real 645 KB HTML page; also via pool).
  `code` comes from `products[].code` in the listing response.
- **Meesho search**: `POST https://www.meesho.com/api/v1/products/search`
  with body `{"query":"shoes","page":1,"offset":0,"limit":5,"type":"text_search"}`
  — direct route; returns full catalog JSON (name, prices, images). Meesho
  product pages/details are still 403 (use `stealth_browser.py`/nodriver for
  rendered product pages, or stick to the search data).

Through the service (engine path):

```bat
REM Ajio listings via free pool
curl.exe -X POST http://127.0.0.1:1712/fetch -H "X-API-Key: KEY" -H "Content-Type: application/json" ^
  -d "{\"url\":\"https://www.ajio.com/api/search?fields=SITE&currentPage=0&pageSize=45&format=json&query=shoes\",\"route\":\"pool\"}"

REM Meesho search via own IP
curl.exe -X POST http://127.0.0.1:1712/fetch -H "X-API-Key: KEY" -H "Content-Type: application/json" ^
  -d "{\"url\":\"https://www.meesho.com/api/v1/products/search\",\"method\":\"POST\",\"headers\":{\"Content-Type\":\"application/json\"},\"body\":\"{\\\"query\\\":\\\"shoes\\\",\\\"page\\\":1,\\\"offset\\\":0,\\\"limit\\\":5,\\\"type\\\":\\\"text_search\\\"}\",\"route\":\"direct\"}"
```

Endpoints can change without notice — keep a cheap sanity check (status 200 +
body length) in the job.

## Verdict semantics (avoid false "Down")

- Free-proxy timeout/403 ⇒ retry or classify as `proxy_error`, not "target down".
- For status checks and user-visible evidence, use the official API or
  `route=direct` — a stable IP.
- Expect the free pool to fluctuate (30–250). If `active_proxies` is low, wait
  one verify cycle or `POST /reload`; the pool re-verifies continuously and
  publishes verified proxies progressively.
- Explicit error contract from `/fetch`: `ok:false` + `error`
  (`no active proxies available`, `no minted cookies`, ...) and, for the
  tunnel, `502 ... country=XX` — map these to internal retries, not to
  user-facing downtimes.

## Running the service (stable form)

```bat
rem from this folder, after: copy proxy-service-config.example.env proxy-service-config.env
venv\Scripts\python.exe -u Proxy-api.py
```

`-u` (unbuffered) + the built-in `faulthandler` make any future crash leave a
readable traceback in the console/log. The refresh loop is crash-isolated
since 2026-10-17.

## Security & hygiene

- **Free "residential" proxies are frequently hijacked devices** — FBI (AVrecon/SocksEscort,
  ~369k routers sold as residential proxies), Google (IPIDEA SDKs), BitSight
  (~15% active malware, ~50% for IPIDEA), NDSS (16,923 content-manipulating
  proxies). Never route logins,
  cookies, tokens or API keys through free proxies.
- `proxy-service-config.env` (API key + tunnel key) and
  `residential-proxies.txt` (provider credentials) are **gitignored**.
  Never copy them into the engine repo or `.env.example` files.
- Rotate keys by editing the config and restarting; both keys are plain
  HMAC-style shared secrets — treat them like passwords.
- Tunnel = localhost only by default (`127.0.0.1:1909`). Do not expose it.

## License & provenance

- This folder is a local instance of a **third-party educational project**
  ("educational/personal use" disclaimer); no LICENSE file was found in the
  source tree.
- Consequence: **keep it internal.** Do not commit it into the engine repo and
  do not redistribute it. Integrate over localhost (REST/tunnel), not by
  vendoring the code.
- All 2026-10-17 additions (fetch routing, direct/unlock, nodriver engine,
  Akamai mint/replay, tunnel country pinning, stability hardening) are local
  work for this instance.
