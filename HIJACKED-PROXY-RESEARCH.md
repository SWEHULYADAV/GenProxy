# Hijacked Devices in "Free/Residential" Proxy Lists — Research Report

Date: 2026-10-17 · Scope: free/open-source only (paid options intentionally out of scope)
Audience: the engine project / its agent. Purpose: report what is actually hijacked
in "free residential" proxy lists, verify consent-based free alternatives from
official docs, and state the honest consequence for the engine.

---

## TL;DR

1. **A legitimately free, consent-based "residential proxy pool" essentially does
   not exist.** The free-list supply of "residential" IPs is dominated by
   **hijacked devices** — infected SOHO routers, IoT, Android/Windows hosts —
   plus **honeypots** and **ad/malware-injecting** proxies.
2. Even *paid* "residential" brands have been shown to source a large share of
   exit nodes from **unwitting users and compromised devices** (IPIDEA, Hola/Luminati,
   AVrecon/SocksEscort).
3. The **only consent-based free networks** are volunteer-run privacy networks —
   **Tor**, **I2P** (and Tor's **Snowflake**). These are **not** residential-proxy
   pools and are **blocked** by the hard targets we care about (Akamai/DataDome/AWS WAF).
4. Therefore the honest rule for the engine: **never trust free-list "residential"
   proxies**, and **never route authenticated traffic through free proxies**.

---

## Part 1 — What is hijacked (evidence)

### 1.1 FBI / IC3 FLASH: AVrecon → SocksEscort (March 2026) — OFFICIAL
- Threat actors compromised **~369,000 routers and IoT devices** (163 countries)
  and **sold access as "residential proxies"** via the **SocksEscort** service.
- Malware **AVrecon** (C, MIPS/ARM) infects **1,200 device models** (Cisco, D-Link,
  Hikvision, **MikroTik**, Netgear, TP-Link, Zyxel), often by exploiting **RCE /
  command injection** on unpatched/EOL devices; some firmware flashes make the
  infection **permanent** (update mechanism disabled).
- Used for ad fraud, password spraying, banking fraud, marketplace fraud,
  romance fraud.
- Takedown by FBI + EUROPOL + Dutch police + others.
- **Source:** https://www.ic3.gov/CSA/2026/260312.pdf (FBI IC3 FLASH, official)

### 1.2 Google Threat Intelligence Group: IPIDEA (Jan 2026) — OFFICIAL
- IPIDEA + **~19 apparently-independent brands** (360 Proxy, 922 Proxy, ABC Proxy,
  Cherry Proxy, Door VPN, Galleon VPN, IP2World, **PIA S5 Proxy**, PY Proxy,
  Radish VPN, Tab Proxy, …) secretly enrolled devices.
- Mechanism: **trojanized apps + SDKs** (Packet SDK, Hex SDK, Earn SDK, Castar SDK)
  in **600+ Android apps** and **3,000+ Windows binaries** masquerading as
  OneDriveSync / Windows Update.
- "Free VPN" apps **also** join devices to the network without clear disclosure.
- Fed botnets **BadBox 2.0, Aisuru, Kimwolf**; **550+ threat groups** observed in
  one week using IPIDEA exits (China, DPRK, Iran, Russia …).
- **Source:** https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network

### 1.3 HUMAN Satori / LumiApps SDK → Asocks (March 2024)
- **28 Android apps** (17 posing as free VPNs) used the **LumiApps "Proxylib"**
  Golang library to turn phones into proxies; linked to the **Asocks** residential
  proxy service. Removed from Google Play; Play Protect updated.
- **Source:** https://www.bleepingcomputer.com/news/security/free-vpn-apps-on-google-play-turned-android-phones-into-proxies/

### 1.4 BitSight: residential-proxy economy is subsidized by malware (May 2026)
- **15.49% of distinct egress IPs (8,222,677)** simultaneously flagged for active
  **malware**; **12.78% (6,785,708)** for **riskware**.
- Infected exit nodes harboured **Vo1d, Badbox, RootSTV/Pandoraspear, OpenCandy,
  Gamarue, m0vy**; overlaps between malware and riskware.
- For the IPIDEA cluster they assess the **true infection rate approaches ~50%**
  (sinkhole telemetry saw **3,000,000+ new infections/day**; one day showed
  **302,238 Vo1d infections as exit nodes = 55% of the global Vo1d botnet**).
- **Source:** https://www.bitsight.com/blog/residential-proxy-services-malware-ecosystems

### 1.5 "Resident Evil" — first systematic study (IEEE S&P 2019)
- Infiltrated 5 RESIP providers; **6.2M RESIP IPs**; **237,029 IoT devices** and
  **4,141 PUP hosts** likely **compromised**.
- **None of the 5 providers is fully consent-based**; even **Luminati** (now
  Bright Data) was found using suspiciously compromised residential hosts.
- Illicit ops: blackhat SEO, fast-fluxing, phishing, malware hosting.
- **Source:** https://doi.org/10.1109/sp.2019.00011

### 1.6 "Free Proxies Unmasked" — 30-month longitudinal study (NDSS 2024)
- **640,600 free proxies** from 11 providers; only **34.5%** ever active.
- **4,452 CVEs** on proxy IPs; **1,755 RCE-capable**, **2,036 privilege-escalation**;
  **42,206** IPs appear to run **MikroTik**; **16,923 proxies manipulate content**.
- Conclusion: "many free proxies likely result from **compromised devices** rather
  than intentional deployments."
- **Sources:** https://arxiv.org/abs/2403.02445 · https://doi.org/10.14722/madweb.2024.23035

### 1.7 ProxyTorrent / Ciao (WWW 2018; ACM ToW 2019)
- <2% of announced free proxies actually proxy traffic; of those, **~10% daily are
  malicious** (ad injection, TLS interception, cryptojacking).
- **Sources:** https://dl.acm.org/doi/10.1145/3178876.3186086 · https://doi.org/10.1145/3360695

### 1.8 ProxyScan (NDSS 2018)
- **38%** of open HTTP proxies modify content; **5.15%** malicious (47% ad
  injection, 39% fingerprinting, 12% malware redirects).
- **Source:** https://www3.cs.stonybrook.edu/~mikepo/papers/proxyscan.ndss18.pdf

### 1.9 Hola / Luminati — "voluntary botnet" (2015)
- Free users' idle bandwidth sold as exit nodes (Luminati); used in a **DDoS
  (8chan)**; users largely **uninformed**; sales rep: "We have no idea what you
  are doing on our platform."
- **Sources:** https://www.theregister.com/on-prem/2015/05/29/free-vpn-hola-is-literally-flogging-access-to-users-devices/1201676
  · https://www.theverge.com/2015/5/29/8685251/hola-vpn-botnet-selling-users-bandwidth
  · https://arstechnica.com/information-technology/2015/06/hola-vpn-used-to-perform-ddos-attacks-violate-user-privacy/

### 1.10 GSEC: public proxy lists as a malware barometer
- "Residential broadband proxies can be used as a reliable barometer and predictor
  of malware spread … the **majority of these proxies are the result of system
  compromise**."
- **Source:** https://www.giac.org/paper/gsec/6541/tracking-malware-public-proxy-lists/112078

### 1.11 Free proxies are also a hazard *against the user*
- Honeypots/MITM (open-proxy honeypots record everything; Worldpool SECURITY.md:
  "79% of free proxies don't support HTTPS"; "Some 'proxies' are honeypots … log
  connecting IPs and may port-scan back"). Never route credentials/tokens through them.
- **Sources:** https://lwn.net/Articles/240120/ · https://github.com/CelestialBrain/worldpool/blob/main/docs/SECURITY.md

---

## Part 2 — Consent-based free options (official docs verified)

| Option | Official docs | Consent model | Notes |
|---|---|---|---|
| **Tor** (volunteer relay network) | https://community.torproject.org/relay/setup/ · https://community.torproject.org/policies/relays/expectations-for-relay-operators/ · https://community.torproject.org/static/files/tor-network-2019.pdf | **Explicit opt-in** by operators; Tor docs: "Never run a relay without the consent of network administrator or machine owner." | Privacy/anonymity network, **not** a residential-proxy pool. Exit IPs are public and banned by the hard targets. |
| **I2P** (free route mixnet) | https://i2p.net/en/docs/ · https://i2p.net/en/docs/overview/threat-model/ · https://i2p.net/en/docs/overview/comparison/ | Fully distributed; **all routers route for others by default** (>95% participate). | No central authority; no dedicated relay operators; hidden services/P2P focused. |
| **Snowflake** (Tor pluggable transport) | (Tor Project docs) | **Volunteer-run** browser-extension proxies for censored users | Consensual; anti-censorship, not scraping. |
| **GNUnet / Freenet (Hyphanet)** | project sites | Volunteer-driven P2P | Research/storage focus; not a proxy pool. |
| **Lokinet** | — | **Not** purely consent-based-free (staked nodes / OXEN incentives) | Mentioned only for completeness. |

**Verified key facts (from the official docs above):**
- Tor relays are run by volunteers who opt in and are told explicitly that running
  a relay requires the machine owner's consent.
- I2P's docs state "over 95% of I2P users relay traffic for others" and that every
  router routes by default; there are no privileged relay operators.
- Neither network is a "residential proxy" service — they are privacy networks, and
  Tor exit nodes are exactly what Akamai/DataDome blocklists target.

**What is NOT consent-based (avoid):**
- Free proxy lists (Public HTTP/SOCKS lists) — majority compromised/hijacked or honeypots.
- "Free VPN / free proxy" apps using monetization SDKs (LumiApps/Proxylib, IPIDEA SDKs).
- Hola-style P2P "free VPN" that sells your idle bandwidth.
- Free MTProto/SOCKS5 proxy lists (Telegram ecosystem) — same hijacked-device problem.

---

## Part 3 — Consequence for the engine / this project

1. **Do not claim or rely on "free residential proxies."** Free-list "residential"
   is, in the evidence, mostly **hijacked devices** (FBI: 369k devices; Google:
   IPIDEA SDKs; Bitsight: ~15% active malware, ~50% for IPIDEA; NDSS: 16,923
   content-manipulating proxies).
2. **Free proxies are unsafe even when they work** — they can be honeypots, MITM,
   ad/malware injectors. **Never** send logins, cookies, tokens, API keys, or
   payment data through them. Only public, unauthenticated GETs.
3. **Consent-based free networks (Tor/I2P/Snowflake) are not a substitute** for
   residential proxies in the engine's use case — they are privacy networks and
   are blocked by the hard targets.
4. **Realistic paths for country/bot-walled markets remain:** own-IP direct route,
   official APIs, paid *consent-based* residential (if ever needed), unlock APIs.
   Free pools are only for public, soft, non-authenticated targets.
5. **Recommendation:** keep the engine integration scoped (per
   `IP-ENGINE-INTEGRATION.md`), and add this finding as a documented risk. Do not
   vendor free-list proxies as a "residential" source.

---

## Source list (all retrieved 2026-10-17)

Official / primary:
- FBI IC3 FLASH (AVrecon/SocksEscort): https://www.ic3.gov/CSA/2026/260312.pdf
- Google GTIG (IPIDEA): https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network
- BleepingComputer (HUMAN/Satori, LumiApps): https://www.bleepingcomputer.com/news/security/free-vpn-apps-on-google-play-turned-android-phones-into-proxies/
- BitSight: https://www.bitsight.com/blog/residential-proxy-services-malware-ecosystems
- Tor relay setup: https://community.torproject.org/relay/setup/
- Tor relay expectations: https://community.torproject.org/policies/relays/expectations-for-relay-operators/
- I2P docs: https://i2p.net/en/docs/
- I2P threat model: https://i2p.net/en/docs/overview/threat-model/
- I2P vs other networks: https://i2p.net/en/docs/overview/comparison/

Academic:
- Resident Evil (IEEE S&P 2019): https://doi.org/10.1109/sp.2019.00011
- Free Proxies Unmasked (NDSS 2024 / arXiv): https://arxiv.org/abs/2403.02445 · https://doi.org/10.14722/madweb.2024.23035
- ProxyTorrent (WWW 2018): https://dl.acm.org/doi/10.1145/3178876.3186086
- ProxyTorrent long-term (ACM ToW 2019): https://doi.org/10.1145/3360695
- ProxyScan (NDSS 2018): https://www3.cs.stonybrook.edu/~mikepo/papers/proxyscan.ndss18.pdf

Press / reference:
- The Register (Hola): https://www.theregister.com/on-prem/2015/05/29/free-vpn-hola-is-literally-flogging-access-to-users-devices/1201676
- The Verge (Hola): https://www.theverge.com/2015/5/29/8685251/hola-vpn-botnet-selling-users-bandwidth
- Ars Technica (Hola): https://arstechnica.com/information-technology/2015/06/hola-vpn-used-to-perform-ddos-attacks-violate-user-privacy/
- Wikipedia (Hola): https://en.wikipedia.org/wiki/Hola_(VPN)
- GSEC (malware via proxy lists): https://www.giac.org/paper/gsec/6541/tracking-malware-public-proxy-lists/112078
- LWN (open-proxy honeypots): https://lwn.net/Articles/240120/
- Worldpool SECURITY.md (free-proxy risk model): https://github.com/CelestialBrain/worldpool/blob/main/docs/SECURITY.md
