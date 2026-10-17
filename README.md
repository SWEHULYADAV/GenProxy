# GenProxy

Local BrightData-style multi-route proxy service & threat intelligence pool.

**Repository:** [https://github.com/SWEHULYADAV/GenProxy](https://github.com/SWEHULYADAV/GenProxy)  
**Author:** Rahul Yadav (SWEHUL Yadav)

## Disclaimer

This project is provided for educational purposes, research, learning, and personal project use only.

Do not use this project for abuse, unauthorized access, illegal scraping, harassment, fraud, privacy violations, service disruption, or any activity that violates the law, a platform's terms, or another party's rights.

If you choose to misuse this project in any way, you are solely responsible for your own actions and any legal, financial, technical, or other consequences that follow.

The author, Rahul Yadav (SWEHUL Yadav), is not responsible for misuse of this project.

This project gives you a local proxy platform that:

- collects free public proxies from many sources
- verifies them and keeps only active working proxies in rotation
- removes failed proxies from live rotation immediately
- retries requests with another active proxy automatically
- remembers which proxies worked per target domain (per-domain memory)
- pulls country-targeted lists so `country=XX` selection spans many countries
- exposes both a REST API and a standard HTTP proxy tunnel
- can be used from almost any language, framework, app, SDK, plugin, or automation tool

The core idea is simple:

1. Run the service locally.
2. Get one local proxy URL or one local API URL.
3. Use that in your project the same way you would use a paid proxy provider.

This is a local proxy service first.
Optional browser stealth helpers are included separately for cases where browser-level fingerprint handling matters.

## Quick Summary

Main local endpoints:

- REST API: `http://127.0.0.1:1712`
- Proxy tunnel: `http://127.0.0.1:1909`
- Authenticated tunnel: `http://proxy:YOUR_PROXY_KEY@127.0.0.1:1909`

Main files:

- [app.py](file:///c:/Users/Admin/Desktop/Proxy_Generation-main/app.py) - single root application entry point (`python app.py [api|live|harvest|mcp]`)
- [backend/](file:///c:/Users/Admin/Desktop/Proxy_Generation-main/backend/) - all backend modules & engine files:
  - [backend/Proxy-api.py](file:///c:/Users/Admin/Desktop/Proxy_Generation-main/backend/Proxy-api.py) - local API service & HTTP proxy tunnel
  - [backend/proxy_core.py](file:///c:/Users/Admin/Desktop/Proxy_Generation-main/backend/proxy_core.py) - source collection, validation, scoring, active pool logic
  - [backend/proxy_sources.py](file:///c:/Users/Admin/Desktop/Proxy_Generation-main/backend/proxy_sources.py) - the free proxy list URLs (edit here when a list dies; `python app.py sources` finds dead ones)
  - [backend/Live-proxies.py](file:///c:/Users/Admin/Desktop/Proxy_Generation-main/backend/Live-proxies.py) - live proxy monitor window
  - [backend/proxy_mcp.py](file:///c:/Users/Admin/Desktop/Proxy_Generation-main/backend/proxy_mcp.py) - MCP server for AI agent operations
  - [backend/stealth_browser.py](file:///c:/Users/Admin/Desktop/Proxy_Generation-main/backend/stealth_browser.py) - stealth browser automation helper
  - [backend/direct_fetch.py](file:///c:/Users/Admin/Desktop/Proxy_Generation-main/backend/direct_fetch.py) - direct fetch client with Chrome TLS print
  - [backend/Tor-manager.py](file:///c:/Users/Admin/Desktop/Proxy_Generation-main/backend/Tor-manager.py) - multi-instance local Tor manager
- [requirements.txt](file:///c:/Users/Admin/Desktop/Proxy_Generation-main/requirements.txt) - all consolidated Python dependencies
- [proxy-service-config.example.env](file:///c:/Users/Admin/Desktop/Proxy_Generation-main/proxy-service-config.example.env) - environment configuration template
- [residential-proxies.example.txt](file:///c:/Users/Admin/Desktop/Proxy_Generation-main/residential-proxies.example.txt) - template for your own pinned residential / ISP proxies

## What This Project Really Is

Think of this as a local proxy provider running on your machine.

Instead of paying a remote provider and calling their proxy endpoint, you run this locally and point your apps at:

- `http://127.0.0.1:1909` as a normal proxy
- or `http://127.0.0.1:1712/fetch` and `http://127.0.0.1:1712/proxy` as API endpoints

It is designed so that your app does not need to know about hundreds of individual free proxies.
Your app talks only to this local service.
This service handles:

- source collection
- validation
- active-only filtering
- retry and failover
- basic header humanization
- live rotation

## Important Reality Check

This project uses free public proxies.

That means:

- many proxies are unstable
- some proxies die quickly
- some proxies get blocked by target websites
- most free proxies are datacenter proxies, not true residential proxies

If you need true residential IPs, you can plug in your own (paid) ones — see
"Residential & Paid Proxies (Bring Your Own)" below.

So this project can behave like a local proxy provider, but it cannot promise paid-provider reliability.
What it does promise is that inside the local service:

- only working proxies are kept active
- failed proxies are removed from live rotation immediately
- retries move to the next active proxy
- the background verifier can re-add a proxy later if it recovers

## Core Behavior

### Active-only rotation

The service does not blindly use every proxy it finds.

It:

1. collects candidates from many sources
2. verifies them
3. keeps only active working proxies in the live pool
4. rotates requests only through the active pool
5. drops a proxy from live rotation immediately when a real runtime request fails

That last part matters.
This is not just scheduled validation.
If a proxy fails during a real request, it is removed from current live rotation right away.

### Retry and failover

If a request fails:

1. first proxy is tried
2. if it fails or looks blocked, the next active proxy is tried
3. if that fails, the next one is tried
4. the service returns the result if any active proxy succeeds

### Anti-repeat behavior

When alternatives are available, the service avoids reusing the exact same proxy back-to-back.

### Block detection

For REST fetch mode, the service can treat these as failure/block signals and move on:

- `403`
- `429`
- `503`
- common Cloudflare/block markers
- common captcha-page markers

## Architecture

High-level flow:

```text
public proxy sources
    ->
candidate collection
    ->
proxy verification
    ->
active working pool
    ->
local API and local proxy tunnel
    ->
your project
```

Runtime components:

- `proxy_core.py` manages candidates, scores, verification, and active pool state
- `Proxy-api.py` exposes local endpoints and proxy tunnel behavior
- `Live-proxies.py` gives a visual live monitor
- `stealth_browser.py` is optional and only for browser-level use cases

## Installation

### 1. Open the project folder

```bat
cd "C:\Users\Admin\Desktop\Proxy_Generation-main"
```

### 2. Create a virtual environment

```bat
python -m venv venv
```

Requires Python 3.11 or newer.

### 3. Install Python dependencies

All dependencies (core, stealth browser, dev, and MCP) are consolidated into a single `requirements.txt`:

```bat
venv\Scripts\pip install -r requirements.txt
```

If you use the optional browser engines:

```bat
venv\Scripts\python -m cloakbrowser install
venv\Scripts\python -m camoufox fetch
venv\Scripts\playwright install chromium
```

### 4. Create your personal local config

After installing dependencies, run the Python setup tool:

```bash
python app.py setup
```

This:
- Auto-generates cryptographically secure API & tunnel keys
- Generates `proxy-service-config.env` with sensible defaults
- Displays your private REST API and HTTP tunnel endpoints

After setup, your normal launcher is simply:

```bash
python app.py
```

## Launch Modes (100% Pure Python)

### Option 1. Run the Proxy API Service (Default)

```bash
python app.py
```

Binds to local-only addresses:
- REST API: `http://127.0.0.1:1712`
- HTTP Proxy Tunnel: `http://127.0.0.1:1909`

### Option 2. Run both the API Service & Live Terminal Monitor

```bash
python app.py both
```

Starts both the live monitor and the API background server.

### Option 3. Run only the Live Terminal Monitor

```bash
python app.py live
```

### Option 4. Run Model Context Protocol (MCP Server for AI Agents)

```bash
python app.py mcp
```

### Option 5. Warmup mode

```bat
venv\Scripts\python Proxy-api.py --warmup --api-key MY_API_KEY --tunnel-api-key MY_PROXY_KEY
```

`--warmup` means the service waits for one full pool build before becoming available.
This is useful when you want the pool ready before your app starts sending traffic.

## Recommended Local Startup

For normal local use:

```bat
venv\Scripts\python Proxy-api.py --warmup --log-requests --api-key MY_API_KEY --tunnel-api-key MY_PROXY_KEY
```

For protected local use:

```bat
venv\Scripts\python Proxy-api.py --warmup --api-key MY_API_KEY --tunnel-api-key MY_PROXY_KEY
```

That gives you:

- API auth through `X-API-Key`
- tunnel auth through standard proxy credentials

## Local URLs You Will Use

### Normal proxy tunnel

```text
http://127.0.0.1:1909
```

### Authenticated proxy tunnel

```text
http://proxy:MY_PROXY_KEY@127.0.0.1:1909
```

`MY_PROXY_KEY` is a password that you choose yourself when starting the service with `--tunnel-api-key`.
It is not auto-generated by the project.

Example:

```bat
venv\Scripts\python Proxy-api.py --tunnel-api-key mysecret123
```

Then the authenticated proxy URL becomes:

```text
http://proxy:mysecret123@127.0.0.1:1909
```

### REST API base

```text
http://127.0.0.1:1712
```

### Raw fetch endpoint

```text
http://127.0.0.1:1712/proxy?url=https://example.com
```

### JSON fetch endpoint

```text
http://127.0.0.1:1712/fetch
```

## Endpoints

### `GET /status`

Shows service health and active pool summary.

Example:

```bat
curl http://127.0.0.1:1712/status
```

You can expect fields like:

- `active_proxies`
- `known_records`
- `best_proxy`
- `sources_count`
- `progress`
- `last_summary`

### `GET /stats`

Shows pool distribution by:

- protocol
- country
- anonymity
- proxy type (residential / datacenter / mobile / tor / unclassified)
- score

`GET /stats` also returns `residential_count`, `tor_count` and `manual_count`.

### `GET /coverage`

Country coverage report — which ISO-3166 countries your live pool can currently serve:

- `covered_countries` / `target_countries` / `coverage_percent`
- `by_country` — active proxy count per country
- `missing` — ISO-2 codes with no active proxy right now

Use it when your scraper needs proxies from many specific countries.

Records from the built-in country-targeted sources (proxyscrape v4 + proxifly
free-proxy-list, ~185 ISO codes by default, controlled by `--country-sources`)
are pre-tagged with the list's country, so coverage fills in immediately as
refresh cycles run; geo enrichment only fills gaps for records from other
sources.

Example:

```bat
curl -H "X-API-Key: YOUR_KEY" "http://127.0.0.1:1712/coverage"
```

### `GET /proxies`

Returns active proxies only.

Common filters:

- `protocol=http`
- `protocol=socks4`
- `protocol=socks5`
- `country=US`
- `anonymity=elite`
- `proxy_type=residential`
- `min_score=0.5`
- `limit=50`

Example:

```bat
curl "http://127.0.0.1:1712/proxies?protocol=http&anonymity=elite&min_score=0.4&limit=20"
```

### `GET /next`

Returns the next active proxy in rotation.

Example:

```bat
curl "http://127.0.0.1:1712/next?protocol=socks5&min_score=0.5"
```

### `GET /random`

Returns a random active proxy from the current live pool.

### `GET` or `POST /proxy`

Fetches the target URL through the proxy pool and returns the raw target response.

This is useful when your app wants the target site's response body directly.

Example:

```bat
curl "http://127.0.0.1:1712/proxy?url=https://httpbin.org/ip"
```

### `GET` or `POST /fetch`

Fetches the target URL through the proxy pool and returns JSON metadata.

This is useful when your app wants:

- which proxy was used
- how many attempts were made
- final URL
- response headers
- response body text

Example:

```bat
curl -X POST http://127.0.0.1:1712/fetch ^
  -H "Content-Type: application/json" ^
  -d "{\"url\":\"https://httpbin.org/ip\",\"max_attempts\":10,\"min_score\":0.4}"

curl -X POST http://127.0.0.1:1712/fetch ^
  -H "Content-Type: application/json" ^
  -d "{\"url\":\"https://example.com\",\"country\":\"DE\",\"proxy_type\":\"residential\"}"
```

### `POST /reload`

Forces an immediate refresh cycle.

Example:

```bat
curl -X POST http://127.0.0.1:1712/reload
```

### `GET /tunnel-status`

Shows proxy tunnel usage stats.

## REST API Request Options

For `/fetch` and `/proxy`, common fields are:

- `url`
- `method`
- `headers`
- `body`
- `timeout`
- `max_attempts`
- `expected_status`
- `pool_limit`
- `min_score`
- `allow_redirects`
- `session_id`
- `min_proxy_interval`
- `country` — only use proxies from this ISO-2 country (e.g. `"DE"`)
- `proxy_type` — `residential` / `datacenter` / `mobile` / `tor`

Example JSON body:

```json
{
  "url": "https://example.com",
  "method": "GET",
  "headers": {
    "Accept": "text/html"
  },
  "timeout": 20,
  "max_attempts": 10,
  "pool_limit": 50,
  "min_score": 0.4,
  "allow_redirects": true,
  "session_id": "user-1",
  "min_proxy_interval": 0,
  "country": "DE",
  "proxy_type": "residential"
}
```

## Authentication

### API auth

Start with:

```bat
venv\Scripts\python Proxy-api.py --api-key MY_API_KEY
```

Use with:

```bat
curl -H "X-API-Key: MY_API_KEY" http://127.0.0.1:1712/status
```

### Tunnel auth

Start with:

```bat
venv\Scripts\python Proxy-api.py --tunnel-api-key MY_PROXY_KEY
```

What `MY_PROXY_KEY` means:

- it is the tunnel password you choose yourself
- the project does not generate it automatically
- whatever value you pass to `--tunnel-api-key` becomes the tunnel password
- the default username is `proxy`

Use with:

```text
http://proxy:MY_PROXY_KEY@127.0.0.1:1909
```

Concrete example:

```bat
venv\Scripts\python Proxy-api.py --tunnel-api-key rahul_proxy_2025
```

Then use:

```text
http://proxy:rahul_proxy_2025@127.0.0.1:1909
```

You can also change the tunnel auth username:

```bat
venv\Scripts\python Proxy-api.py --tunnel-api-key MY_PROXY_KEY --tunnel-auth-user rahul
```

Then the proxy URL becomes:

```text
http://rahul:MY_PROXY_KEY@127.0.0.1:1909
```

## Output Files

Each run creates a timestamped folder under `output`.

Typical files:

- `active_proxies.json`
- `session_info.json`

These help you inspect:

- current active pool
- session metadata
- last refresh summary

Tor-manager writes its own files next to the project: `tor-proxies.txt` (fed to
the service every cycle) and `tor-data\` (per-country Tor state + logs).

## How To Use It In Any App

There are two main integration styles.

### Style 1. Use the local tunnel as a normal proxy

This is the easiest option when your language or SDK already supports HTTP proxies.

Your app points to:

```text
http://127.0.0.1:1909
```

or:

```text
http://proxy:MY_PROXY_KEY@127.0.0.1:1909
```

Best for:

- `requests`
- `axios`
- `fetch` wrappers
- Scrapy
- Playwright
- Puppeteer
- Selenium
- browsers
- crawlers
- API clients
- most SDKs with proxy support

### Style 2. Use the local REST API

This is best when your app:

- does not support proxy config directly
- wants metadata about attempts and used proxies
- wants a stable local API contract

Your app calls:

- `http://127.0.0.1:1712/proxy?url=...`
- or `http://127.0.0.1:1712/fetch`

## SDK / Plugin / Integration Explanation

There is no separate custom SDK file in this repo right now.
(An MCP server for AI agents is included separately as `proxy_mcp.py` — see the MCP section below.)
Instead, this service is intentionally built around universal standards:

- HTTP proxy tunnel
- HTTP REST API

That means almost every language and framework can use it already without needing a special plugin.

If a tool supports:

- HTTP proxy configuration
- SOCKS/HTTP proxy field
- custom base URL
- web requests

then it can integrate with this project.

So in practice, this project already behaves like a provider integration layer.

You can also build your own lightweight SDK wrapper on top of:

- `/fetch`
- `/proxy`
- `/next`
- `/proxies`
- `/stats`

## Language Examples

### Python

Using `requests`:

```python
import requests

proxy_url = "http://127.0.0.1:1909"
proxies = {
    "http": proxy_url,
    "https": proxy_url,
}

r = requests.get("https://httpbin.org/ip", proxies=proxies, timeout=30)
print(r.text)
```

Using REST API:

```python
import requests

r = requests.post(
    "http://127.0.0.1:1712/fetch",
    json={
        "url": "https://httpbin.org/ip",
        "max_attempts": 10,
        "min_score": 0.4
    },
    timeout=60,
)
print(r.json())
```

### JavaScript / Node.js

Using `axios` with the REST API:

```js
const axios = require("axios");

async function main() {
  const res = await axios.post("http://127.0.0.1:1712/fetch", {
    url: "https://httpbin.org/ip",
    max_attempts: 10,
    min_score: 0.4
  });

  console.log(res.data);
}

main();
```

Using a proxy-aware client:

```js
const axios = require("axios");
const HttpsProxyAgent = require("https-proxy-agent");

const proxy = "http://127.0.0.1:1909";
const agent = new HttpsProxyAgent(proxy);

axios.get("https://httpbin.org/ip", {
  httpAgent: agent,
  httpsAgent: agent
}).then(res => {
  console.log(res.data);
});
```

### Browser JavaScript

Direct browser requests usually use the REST API, not the tunnel.

```js
fetch("http://127.0.0.1:1712/fetch", {
  method: "POST",
  headers: {
    "Content-Type": "application/json"
  },
  body: JSON.stringify({
    url: "https://httpbin.org/ip",
    max_attempts: 10
  })
})
  .then(r => r.json())
  .then(console.log);
```

### Go

Using the tunnel:

```go
package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
)

func main() {
	proxyURL, _ := url.Parse("http://127.0.0.1:1909")
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	resp, err := client.Get("https://httpbin.org/ip")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Println(string(body))
}
```

### Java

Using the tunnel:

```java
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;

public class Main {
    public static void main(String[] args) throws Exception {
        Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", 1909));
        URLConnection conn = new URL("https://httpbin.org/ip").openConnection(proxy);
        InputStream in = conn.getInputStream();
        System.out.println(new String(in.readAllBytes()));
    }
}
```

### C#

Using the tunnel:

```csharp
using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

class Program
{
    static async Task Main()
    {
        var handler = new HttpClientHandler
        {
            Proxy = new WebProxy("http://127.0.0.1:1909"),
            UseProxy = true
        };

        using var client = new HttpClient(handler);
        var body = await client.GetStringAsync("https://httpbin.org/ip");
        Console.WriteLine(body);
    }
}
```

### PHP

Using the tunnel:

```php
<?php
$ch = curl_init("https://httpbin.org/ip");
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_PROXY, "http://127.0.0.1:1909");
$response = curl_exec($ch);
curl_close($ch);
echo $response;
```

### Ruby

Using the tunnel:

```ruby
require "net/http"
require "uri"

proxy = URI("http://127.0.0.1:1909")
target = URI("https://httpbin.org/ip")

http = Net::HTTP::Proxy(proxy.host, proxy.port).new(target.host, target.port)
http.use_ssl = true

request = Net::HTTP::Get.new(target)
response = http.request(request)
puts response.body
```

### Rust

Using the tunnel with `reqwest`:

```rust
use reqwest::Proxy;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proxy = Proxy::all("http://127.0.0.1:1909")?;
    let client = reqwest::Client::builder().proxy(proxy).build()?;
    let body = client.get("https://httpbin.org/ip").send().await?.text().await?;
    println!("{}", body);
    Ok(())
}
```

### cURL

Using the tunnel:

```bat
curl -x http://127.0.0.1:1909 https://httpbin.org/ip
```

Using the authenticated tunnel:

```bat
curl -x http://proxy:MY_PROXY_KEY@127.0.0.1:1909 https://httpbin.org/ip
```

Using the REST API:

```bat
curl "http://127.0.0.1:1712/proxy?url=https://httpbin.org/ip"
```

## Common App Integrations

### Scrapy

```python
HTTP_PROXY = "http://127.0.0.1:1909"
HTTPS_PROXY = "http://127.0.0.1:1909"
```

### Playwright

```python
browser = playwright.chromium.launch(
    proxy={"server": "http://127.0.0.1:1909"}
)
```

### Puppeteer

Launch Chromium with:

```text
--proxy-server=http://127.0.0.1:1909
```

### Selenium

Configure browser proxy settings to:

```text
127.0.0.1:1909
```

### Postman

Use the local REST API:

- `POST http://127.0.0.1:1712/fetch`

or set Postman's global proxy to:

- host `127.0.0.1`
- port `1909`

### Electron apps

You can either:

- use the REST API
- or configure Chromium proxy settings to `http://127.0.0.1:1909`

### Any SDK or plugin that supports proxies

Look for settings such as:

- proxy URL
- HTTP proxy
- HTTPS proxy
- outbound proxy
- transport proxy
- network proxy

and set it to:

```text
http://127.0.0.1:1909
```

## MCP Server (AI Agent Control)

`proxy_mcp.py` exposes this service over the Model Context Protocol (stdio), so an AI host
(OpenCode, Claude Desktop, Cursor, ...) can check the pool, start/stop the service, and fetch
targets through the rotating proxies.

Install dependencies:

```bat
venv\Scripts\pip install -r requirements.txt
```

### OpenCode

The project already includes `opencode.json` with the `proxy-generator` server configured.
Run OpenCode in this folder and verify the connection:

```bat
opencode mcp list
```

### Claude Desktop

```bat
venv\Scripts\python -m mcp install proxy_mcp.py --name "Proxy Generator"
```

### Tools exposed

| Tool | What it does |
|---|---|
| `proxy_service_status` | is the service up? (health + PID + config summary) |
| `proxy_service_start` / `proxy_service_stop` | start / stop the local service |
| `proxy_status` / `proxy_stats` / `proxy_tunnel_status` | pool + tunnel health and analytics |
| `proxy_coverage` | which countries the pool can serve + missing ISO-2 codes |
| `proxy_list` / `proxy_next` / `proxy_random` | inspect and pick active proxies |
| `proxy_fetch` | fetch a public URL through the rotating pool (JSON + body) |
| `proxy_reload` | force a pool refresh (rate-limited to once per 60 s) |

Keys are read from `proxy-service-config.env` automatically.
Optional env overrides: `PROXY_MCP_BASE_URL`, `PROXY_MCP_API_KEY`, `PROXY_MCP_TUNNEL_KEY`.

## Residential & Paid Proxies (Bring Your Own)

Free lists are mostly datacenter IPs. To use true residential proxies from a paid
provider (Webshare, IPRoyal, Bright Data, Oxylabs, Decodo, ...), put them in
`residential-proxies.txt` in this folder — one entry per line, all formats accepted:

```text
1.2.3.4:8080
username:password@1.2.3.4:8080
http://username:password@1.2.3.4:8080
socks5://username:password@gate.provider.com:1080
```

Hostnames are supported here; lines starting with `#` and inline `# comments` are ignored.

How the service treats them:

- always kept in the pool — never auto-pruned, even when temporarily down
- verified first in every cycle, so they join the live pool fastest
- tagged `proxy_type=residential` and `manual=true`
- selectable explicitly with `proxy_type=residential` on `/proxies`, `/next`,
  `/random`, `/fetch` (and the MCP tools `proxy_list`, `proxy_next`,
  `proxy_random`, `proxy_fetch`)

Examples:

```bat
curl -H "X-API-Key: YOUR_KEY" "http://127.0.0.1:1712/proxies?proxy_type=residential&limit=20"

curl -X POST http://127.0.0.1:1712/fetch ^
  -H "Content-Type: application/json" ^
  -H "X-API-Key: YOUR_KEY" ^
  -d "{\"url\": \"https://httpbin.org/ip\", \"proxy_type\": \"residential\"}"
```

Free proxies also get a type label automatically from ip-api.com classification
(`hosting=true` → `datacenter`, `mobile=true` → `mobile`, otherwise `residential`),
so `proxy_type=residential` can also match free IPs that are not hosted in datacenters.

`GET /stats` returns a `by_type` breakdown plus `residential_count` and `manual_count`.

## Tor Proxies (Free Country Targeting)

The project ships with a bundled Tor Expert Bundle under `tor\` and a manager
script `Tor-manager.py`. It runs one local Tor instance per country
(`ExitNodes {cc}` + `StrictNodes 1`) on its own SOCKS port and writes the
endpoints to `tor-proxies.txt`, which the proxy service reads every cycle and
tags `proxy_type=tor` with the pinned country — no service restart needed.

Start / inspect / stop:

```bat
venv\Scripts\python Tor-manager.py --status
venv\Scripts\python Tor-manager.py
venv\Scripts\python Tor-manager.py --countries us,de,jp,br
venv\Scripts\python Tor-manager.py --stop
```

(without `--countries` the list from `tor-countries.txt` is used)

Then use them like any other proxies:

```bat
curl -H "X-API-Key: YOUR_KEY" "http://127.0.0.1:1712/proxies?proxy_type=tor"

curl -X POST http://127.0.0.1:1712/fetch ^
  -H "Content-Type: application/json" ^
  -H "X-API-Key: YOUR_KEY" ^
  -d "{\"url\": \"https://example.com\", \"country\": \"DE\"}"
```

Notes:

- Tor exits do not exist in every country (roughly 70-90 countries have exit
  relays). Treat these as pinned country IPs, not a rotating residential pool.
- Bootstrapping takes ~1-2 minutes per start; the first requests can be slow.
- Many sites block Tor exits — use Tor for country reach and BYO residential
  for quality.
- `tor-countries.txt` holds the default country list; `tor-data\` holds
  per-country Tor state and logs (delete it for a full reset).

`GET /coverage` shows exactly which countries are covered or still missing.

## Optional Browser Stealth Helper

The main project is the proxy service.
Browser stealth is optional and uses `stealth_browser.py` (engines, best first):

1. nodriver — real Chrome over CDP with zero automation markers (highest
   stealth score in 2026 tests). **Direct-only**: Chrome's CLI has no
   proxy-auth support, so it is skipped whenever a proxy is requested.
2. CloakBrowser
3. Camoufox
4. Playwright

Auto order: without a proxy, nodriver runs first; with a proxy it is skipped
and CloakBrowser → Camoufox → Playwright are tried.

Install at least one engine (nodriver is a single pip install; Playwright is
the lightest general option):

```bat
REM highest stealth (direct / own-IP only)
venv\Scripts\pip install nodriver
venv\Scripts\python stealth_browser.py https://www.tatacliq.com/ --no-proxy

REM lightest general engine (works with the proxy tunnel)
venv\Scripts\pip install playwright
venv\Scripts\python -m playwright install chromium
venv\Scripts\python stealth_browser.py https://httpbin.org/ip --engine playwright
```

The browser routes through the local tunnel by default. Tunnel credentials are
read automatically from `proxy-service-config.env` (`PROXY_SERVICE_TUNNEL_KEY`
/ `PROXY_SERVICE_TUNNEL_USER`), so authenticated tunnels work without extra
flags. On Windows the helper uses the Proactor event loop because Playwright
needs subprocess support.

More examples:

```bat
REM render a JS-heavy shop page and save it
venv\Scripts\python stealth_browser.py "https://www.flipkart.com/" --engine playwright --wait 4000 --output page.html --screenshot shot.png

REM mobile profile (better for social homepages)
venv\Scripts\python stealth_browser.py "https://www.instagram.com/" --engine playwright --mobile --wait 4000

REM pin one specific pool proxy instead of tunnel rotation (from /next?country=US)
venv\Scripts\python stealth_browser.py "https://example.com/" --proxy "http://IP:PORT" --engine playwright
```

Library example:

```python
import asyncio
from stealth_browser import scrape_url

result = asyncio.run(scrape_url("https://httpbin.org/ip"))
print(result["status"], result["content_length"])
```

Important boundary:

- proxy tunnel handles proxy rotation and failover
- browser helper handles browser-level fingerprint surfaces (JS challenges,
  Canvas/WebGL/Audio/font spoofing, mobile profiles)
- TLS certificate validation stays ON in the browser: intercepting (MITM)
  proxies are rejected loudly instead of silently decrypted
- browser rendering cannot fix bad proxy IP reputation: Cloudflare/Akamai
  sites (Etsy, Meesho, ...) still return 403 to datacenter IPs. Pair the
  browser with your own residential proxies for those targets.

## Direct Fetch (own IP + Chrome TLS fingerprint)

Free datacenter proxies get 403 from Akamai/DataDome/AWS WAF on many Indian
stores — but the *same* pages usually load from a normal ISP/residential IP
when the TLS fingerprint looks like real Chrome. `direct_fetch.py` does exactly
that: **no proxy by default**, `curl_cffi` impersonating Chrome, courteous pacing.
Use it for low/medium volume at human-ish rates.

Live-verified full pages from an ordinary Indian ISP IP (2026-10-17): Myntra
(listing too), Nykaa, Flipkart (search too), JioMart, Croma, Reliance Digital,
Snapdeal, Pinterest, Etsy India, Shopsy (when its edge allows).

```bat
REM single page -> file
venv\Scripts\python direct_fetch.py https://www.myntra.com/shoes --output shoes.html

REM batch from a file, paced, with JSON report
venv\Scripts\python direct_fetch.py --urls-file urls.txt --json report.json --delay 1.5

REM optional: route via your own proxy/residential instead of the local IP
venv\Scripts\python direct_fetch.py URL --proxy http://user:pass@host:port
```

Notes:
- Public https targets only; keep polite pacing (`--delay`) — your IP is the budget.
- Akamai JS-sensor sites (Meesho, Ajio) and DataDome (Etsy US locale) still need
  the browser helper or residential proxies.

## Fetch Routing: pool / direct / unlock

`POST /fetch` (and `GET /proxy`) accept a `route` parameter:

| route | meaning |
|---|---|
| `auto` (default) | hosts in `--unlock-hosts` go through the unlock API; everything else uses the proxy pool |
| `pool` | rotating free/paid proxy pool (as before) |
| `direct` | this machine's own IP via curl_cffi (Chrome TLS print), rate-limited |
| `unlock` | external anti-block API (ScraperAPI/ZenRows/Scrape.do style) |

Direct-route safety: `--direct-concurrency 2` + `--direct-min-interval 1.0`
(max two parallel, one request started per second) so your own IP never looks
like a bot. `/stats` reports `direct_calls`.

Response fields: `ok`, `status_code`, `route`, `final_url`, `body` (text
bodies — HTML/JSON — decoded automatically), `body_base64` (binary bodies),
`headers`, `proxy_*` fields (empty on direct/unlock) and `attempts`.

```bat
REM own IP + real Chrome TLS: full Myntra page
curl.exe -X POST http://127.0.0.1:1712/fetch -H "X-API-Key: %KEY%" -H "Content-Type: application/json" -d "{\"url\":\"https://www.myntra.com/shoes\",\"route\":\"direct\"}"
```

curl_cffi pool backend: with `PROXY_SERVICE_FETCH_CLIENT=curl_cffi` (already the
default in `proxy-service-config.env`) every pool/tunnel fetch gets a real
Chrome TLS fingerprint (JA3/JA4) instead of plain aiohttp — hard blocks on
sniffing edges downgrade to soft challenges. Switch back globally with
`PROXY_SERVICE_FETCH_CLIENT=aiohttp`, or per request with `"http_client": "aiohttp"`.

Unlock API adapter (`route=unlock`, or automatic for `--unlock-hosts`): any GET
template with `{key}` and `{url}` placeholders works:

```
PROXY_SERVICE_UNLOCK_URL_TEMPLATE=http://api.scraperapi.com?api_key={key}&url={url}
PROXY_SERVICE_UNLOCK_API_KEY=YOUR_KEY
PROXY_SERVICE_UNLOCK_HOSTS=meesho.com,etsy.com
```

Free tiers stack to ~6K hard pages/month at $0 (Bright Data Web Unlocker 5K,
ZenRows 5K, Scrape.do 1K) — see `RESEARCH-2026-10-17.md`.

## Akamai cookie mint → replay (`akamai_warm.py`)

For Akamai sensor sites (Myntra / Nykaa / Ajio / JioMart / Meesho), real Chrome
(nodriver) visits the page on your own IP, waits until `_abck` shows the `~-1~`
validated marker, saves all cookies + the exact User-Agent to
`akamai-cookies.json`, and `replay` re-fetches with curl_cffi (same exit IP,
same UA, Chrome TLS):

```bat
venv\Scripts\python akamai_warm.py test https://www.ajio.com/
venv\Scripts\python akamai_warm.py replay https://www.meesho.com/ --output page.html
venv\Scripts\python akamai_warm.py list
```

Honest boundary: `_abck` validation is behavioural and IP-scored; replays can
still be re-challenged, cookies expire (minutes to ~1 hour) and die on any
IP/UA change. Re-run `mint` when replays start failing.

**Ajio/Meesho jugaad (round 4):** Ajio's SPA JSON APIs (`/api/search`,
`/api/p/<code>`) and product HTML (`/p/<code>`) answer curl_cffi directly —
also through the free pool; Meesho's `POST /api/v1/products/search` returns
full catalog JSON on the direct route. Ajio **headful** mint passes
(`~-1~` validated); headless gets Access Denied.

## Tunnel country pinning (engine integration)

The forward-proxy tunnel can now pin the exit country through the username —
one local tunnel, per-route countries:

| Username | Effect |
|---|---|
| `proxy` | any country (classic behaviour) |
| `proxy-sg` / `proxy-country-sg` | force a Singapore exit (`<cc>` = ISO-2) |

```bat
REM country-pinned tunnel route (password = tunnel key)
curl -x http://proxy-sg:TUNNEL_KEY@127.0.0.1:1909 https://api.ipify.org?format=json
```

If the pool has no proxies for that country the tunnel answers
`502 No Proxies Available For Country SG` — an explicit failure instead of a
silently wrong-country exit. `residential-proxies.txt` accepts an explicit
`|CC` tag for provider gateways (`gate.provider.com:8080|SG`) so paid
country residential feeds straight into the same pinning.

## Stability hardening (2026-10-17)

- The pool refresh loop now survives a broken cycle: it logs the traceback and
  keeps retrying instead of freezing the pool (suspected cause of the
  documented silent-death incident).
- `faulthandler` is enabled at startup and stdout/stderr are line-buffered, so
  hard crashes leave a stack trace even when the service is started without
  `-u`.
- Recommended start command: `python app.py`.

## License, provenance & secrets hygiene

- This folder is an educational and testing project.
- `.gitignore` now excludes `proxy-service-config.env`, `residential-proxies.txt`,
  `akamai-cookies.json` and `output/`; a blank-key
  `proxy-service-config.example.env` and `residential-proxies.example.txt` are
  provided for reference.

## CLI Reference

Most important flags for `app.py`:

| Flag | Default | Meaning |
|---|---|---|
| `--host` | `127.0.0.1` | API bind host |
| `--port` | `1712` | API bind port |
| `--public-base-url` | empty | public URL label if exposed elsewhere |
| `--output-root` | `output` | run output folder root |
| `--session-prefix` | `api` | run folder prefix |
| `--max-concurrent` | `120` | source fetch and validation concurrency |
| `--fetch-timeout` | `8.0` | source download timeout |
| `--verify-timeout` | `8.0` | proxy validation timeout |
| `--request-timeout` | `20.0` | target request timeout |
| `--request-concurrency` | `200` | outbound target request concurrency |
| `--refresh-delay` | `5.0` | refresh loop delay |
| `--update-interval` | `120.0` | source refresh interval |
| `--verify-interval` | `60.0` | active pool re-check interval |
| `--auto-save-interval` | `15.0` | minimum JSON save interval |
| `--max-candidates` | `2000` | max candidates per cycle (env `PROXY_SERVICE_MAX_CANDIDATES`) |
| `--verify-batch-size` | `250` | active proxy verify batch size (env `PROXY_SERVICE_VERIFY_BATCH_SIZE`) |
| `--min-success-rate` | `0.35` | minimum acceptable success rate |
| `--max-failures` | `3` | max consecutive failures |
| `--stale-after` | `1800` | stale proxy lifetime in seconds |
| `--max-response-time` | `12.0` | max average proxy response time |
| `--source-file` | empty | custom extra source list |
| `--country-sources` | `default` | per-country list sources (`default` / `off` / `us,de,jp,...`) |
| `--fetch-client` | `auto` | HTTP client for pool fetches (`auto`/`aiohttp`/`curl_cffi`, env `PROXY_SERVICE_FETCH_CLIENT`) |
| `--curl-workers` | `64` | curl_cffi worker threads (env `PROXY_SERVICE_CURL_WORKERS`) |
| `--curl-impersonate` | `chrome` | curl_cffi impersonation profile (`chrome`, `firefox`, `safari`, ...) |
| `--direct-client` | `curl_cffi` | HTTP client for the direct route (own IP) |
| `--direct-concurrency` | `2` | max parallel own-IP (direct route) fetches |
| `--direct-min-interval` | `1.0` | minimum seconds between direct-route fetches |
| `--unlock-url-template` | empty | unlock API GET template with `{key}` + `{url}` |
| `--unlock-api-key` | empty | unlock API key |
| `--unlock-timeout` | `60` | unlock API request timeout (seconds) |
| `--unlock-hosts` | empty | host suffixes auto-routed via unlock when `route=auto` |
| `--warmup` | off | build pool before accepting traffic |
| `--proxy-delay` | `0.1` | delay between proxy attempts |
| `--rotate-ua` | on | rotate HTTP headers and user-agent |
| `--no-shuffle-proxies` | off | preserve rank order instead of shuffling |
| `--api-key` | required | REST API auth key |
| `--cors-origin` | `*` | CORS allow origin |
| `--max-response-mb` | `10.0` | max response size |
| `--log-requests` | off | request logging |
| `--tunnel-host` | `127.0.0.1` | tunnel bind host |
| `--tunnel-port` | `1909` | tunnel port |
| `--tunnel-max-attempts` | `5` | attempts per tunnel request |
| `--tunnel-relay-timeout` | `120.0` | tunnel idle timeout |
| `--tunnel-api-key` | required when tunnel is enabled | standard proxy auth password |
| `--tunnel-auth-user` | `proxy` | standard proxy auth username |

Pool tuning (optional, set in `proxy-service-config.env` — both `app.py` and MCP `proxy_service_start` pass them through):

- `PROXY_SERVICE_MAX_CANDIDATES` (default `2000`) — candidates kept per source cycle
- `PROXY_SERVICE_VERIFY_BATCH_SIZE` (default `250`) — active proxies re-checked per verify cycle
- `PROXY_SERVICE_COUNTRY_SOURCES` (default `default`) — `off` or `us,de,jp,...`
- `PROXY_SERVICE_RESIDENTIAL_FILE` / `PROXY_SERVICE_TOR_FILE` — custom file paths

## Threat Intelligence & Forensic Evidence Export

Export filtered proxies and forensic evidence either via the REST API or directly from the CLI for threat intelligence reporting:

### 1. Direct CLI Export (No Server Needed)
```bash
# Export plain text proxies (IP:PORT)
python app.py export --format txt --country US --speed-tier fast -o us_fast_proxies.txt

# Export threat intelligence forensic CSV (ready for reporting to seniors / agencies)
python app.py export --format csv -o proxy_evidence.csv

# Export full forensic JSON bundle
python app.py export --format json -o proxy_evidence.json
```

### 2. Live API Export Endpoints
- `GET /export/proxies.txt` (or `/proxies.txt`): Raw newline-delimited `host:port` (supports `?country=`, `?protocol=`, `?speed_tier=`, `?anonymity=`, `?with_scheme=1`).
- `GET /export/evidence.csv`: Complete CSV spreadsheet with IP, port, protocol, country, anonymity, response times, and timestamps for reporting.
- `GET /export/evidence.json`: Audit-grade JSON evidence bundle.

## Startup Checklist

When using this in a real app, the practical setup order is:

1. install dependencies
2. run `Start-Live-Proxies.bat` or start `Proxy-api.py`
3. wait until `/status` shows active proxies
4. test with `http://127.0.0.1:1712/status`
5. test tunnel with `curl -x http://127.0.0.1:1909 https://httpbin.org/ip`
6. point your real project to the local tunnel or local REST API

## Testing Commands

### Syntax check

```bash
python -m py_compile app.py backend/proxy_core.py backend/Proxy-api.py backend/stealth_browser.py
```

### Status check

```bat
curl http://127.0.0.1:1712/status
```

### Rotation check

```bat
for /L %i in (1,1,5) do curl "http://127.0.0.1:1712/proxy?url=http://api.ipify.org%%3Fformat%%3Djson"
```

### Auth check

```bat
curl -H "X-API-Key: MY_API_KEY" http://127.0.0.1:1712/status
curl -x http://proxy:MY_PROXY_KEY@127.0.0.1:1909 https://httpbin.org/ip
```

## Best Practices

- keep the service local unless you really need LAN exposure
- use `--api-key` and `--tunnel-api-key` if exposing it beyond your machine
- prefer `--warmup` before connecting your app
- use `max_attempts >= 10` for unstable targets
- use `min_score >= 0.4` when you want more stable proxies
- use `session_id` when the same logical user flow needs the same proxy
- monitor `/status` and `/stats` if your app depends on sustained throughput

## Limits

This service does a lot for free proxies, but some limits are real:

- free proxies are not as reliable as premium providers
- target websites may still block some datacenter IPs
- browser fingerprint handling is not the same thing as proxy rotation
- some apps only support HTTP proxy config and not custom API flows

Still, for local use, development, research, scraping experiments, proxy rotation workflows, and universal proxy integration, this project is designed to be a strong one-stop setup.

## Credits and Acknowledgements

This project stands on top of a number of useful open-source libraries, tools, and public proxy-list projects.
Credit is due to the maintainers and contributors behind them.

### Core libraries used by this project

- `aiohttp` for the async HTTP client and server foundation
- `aiohttp-socks` for SOCKS proxy support
- `python-socks` for low-level SOCKS tunnel connectivity
- `requests` for simple HTTP integration examples
- `rich` for the live terminal UI and readable console output

### Optional browser helper ecosystem

- `CloakBrowser` for browser-level stealth and fingerprint resistance
- `Camoufox` for Firefox-based anti-detection support
- `Playwright` for browser automation fallback support

### Public proxy source ecosystem

This project also depends on public proxy-list providers and repositories that publish free proxy data.
Examples include:

- `proxifly/free-proxy-list`
- `TheSpeedX/PROXY-List`
- `monosans/proxy-list`
- `vakhov/fresh-proxy-list`
- `MuRongPIG/Proxy-Master`
- `Zaeem20/FREE_PROXIES_LIST`
- `rdavydov/proxy-list`
- `ProxyScrape`
- `Geonode`
- `proxy-list.download`
- `openproxylist`

The source lists live in [backend/proxy_sources.py](backend/proxy_sources.py): `SOURCES` (one URL per line)
and `COUNTRY_SOURCE_TEMPLATES`. When a list dies or moves, edit that file only; a running service picks the
change up on its next collect cycle.

- Put `#` in front of a line to switch a list off, or move it to `DEAD_SOURCES` (kept there with the date).
- Bare `ip:port` entries in a list whose URL names `socks5` / `socks4` are tested as that protocol.
- JSON APIs (Geonode style: `ip`, `port`, `protocols`, `country`) are read too.
- A URL with `{cc}` / `{CC}` is a country template, expanded for every code in `PROXY_SERVICE_COUNTRY_SOURCES`.
- If the file is missing or an edit breaks it, a running service keeps its previous lists; a fresh start falls
  back to five built-in lists and prints a warning.

Find dead or empty lists:

```powershell
venv\Scripts\python app.py sources                    # every list in backend/proxy_sources.py
venv\Scripts\python app.py sources --countries us,in  # plus the country templates for those codes
```

### How a cycle spends its verification budget

The lists hold hundreds of thousands of entries; one cycle verifies `PROXY_SERVICE_MAX_CANDIDATES` of them.

- Entries that failed are retried later with a growing backoff (15 min, 30 min, 1 h ... up to 6 h), so each
  cycle checks entries it has not just seen dead instead of the same top 2000 again.
- Proxies that worked before go first, then fresh entries from the lists whose proxies pass most often
  (per-list `tested` / `working` counts are saved in the pool JSON under `sources`).
- A new API or live-monitor session starts from the previous session's pool, so a restart is warm.
- An endpoint listed as `http://` that turns out to be SOCKS (or SOCKS4 vs SOCKS5) is kept under the protocol
  that works.
- `proxy_type=residential` means ip-api did not flag the IP as hosting or mobile *and* its ISP / org / AS name
  does not look like a hosting, cloud or backbone network. It is a best guess from public data, not proof of a
  home connection; for guaranteed residential exits, put your own in `residential-proxies.txt`.

### Note on ownership

This project integrates with and builds on top of external libraries and public data sources, but it is not affiliated with, endorsed by, or officially maintained by those third-party projects.

## Final Mental Model

If your app supports a proxy field, use:

```text
http://127.0.0.1:1909
```

If your app supports only HTTP API calls, use:

```text
http://127.0.0.1:1712/fetch
```

If your app wants raw target content through the pool, use:

```text
http://127.0.0.1:1712/proxy?url=YOUR_TARGET_URL
```

That is the whole product shape.
Run it once, then treat it like your own local proxy provider.
