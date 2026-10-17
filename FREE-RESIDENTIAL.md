# Free residential exits — what exists, what to use, what to avoid

Written 2026-10-17 for this local, open-source setup (no paid provider). Companion to `IP-ENGINE-INTEGRATION.md`.

## The honest picture

- **There is no free pool of legitimate residential IPs.** A residential address belongs to a household or a phone
  plan; someone has to agree to relay your traffic through it, and providers pay for that agreement.
- The `residential` tag the service puts on **public free-list** addresses (`/stats`, `residential_active`) only means
  "the geo lookup says this IP is not a datacenter". Those are, in practice, other people's devices — routers, phones,
  PCs with malware or a bundled SDK — whose owners did not agree to this. Do not build client-facing work on them
  (and do not route BrandHawk evidence through them): they are unstable, can tamper with plain-HTTP traffic, and using
  someone's machine without consent is a legal and reputational problem for a brand-protection business.
- What *is* free and legitimate: (1) your own connection, (2) exits you set up yourself on devices whose owners
  agreed, (3) trials of paid services, only to check a market.

## 1. Your own connection — already residential (use this first)

The machine's own ISP address is a residential IP. For Indian marketplaces it is the best exit there is:
`route=direct` on `/fetch` (see `IP-ENGINE-INTEGRATION.md` §2), `direct_fetch.py`, and BrandHawk itself, which runs
from it. Myntra, Nykaa, Flipkart, Snapdeal, Pinterest and others answered full pages from it on 2026-10-17. No proxy,
no setup, no consent question.

## 2. Exits you run on devices whose owner agreed (free, open source, any country)

A small always-on device (Raspberry Pi, old laptop, mini PC) in a home or office in the country you need — a
colleague, a partner, a friend, written consent — runs a SOCKS5 server that only your machine can reach, over a free
private network. You then list it in `residential-proxies.txt` like any proxy, with a country tag.

**On the remote device** (Linux shown; any SOCKS5 server works):

```sh
# Tailscale: free "Personal" plan - its pricing page (checked 2026-10-17) says "up to 6 users", unlimited user devices.
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up
tailscale ip -4                    # e.g. 100.101.102.103  <- this address is only reachable inside your tailnet

# microsocks: a tiny open-source SOCKS5 server (https://github.com/rofl0r/microsocks).
# Usage: microsocks -i listenip -p port -u user -P passw   (default listen is 0.0.0.0 - always set -i)
microsocks -i 100.101.102.103 -p 1080 -u brandhawk -P "a-long-random-password"
```

- Listen **only** on the Tailscale address (`-i`), never on `0.0.0.0`, and always set `-u/-P`. Do not use `-w`/`-1`
  (they let addresses skip the password).
- In the Tailscale admin console add an access rule so only your machine may open port 1080 on that device.
- Run it as a service (systemd) so it survives reboots. If the distro has a `microsocks` package use it, otherwise
  build from source (`make`).

**On this machine:** install Tailscale and sign in to the same tailnet, then check the exit:

```bat
curl.exe --proxy socks5h://brandhawk:a-long-random-password@100.101.102.103:1080 https://api.ipify.org
```

The address printed must be the remote home's public IP (look it up: it should be in the country you expect).

**Add it to `residential-proxies.txt`** (never committed; the file is gitignored):

```
socks5://brandhawk:a-long-random-password@100.101.102.103:1080|MY
```

The `|MY` tag pins the exit country, so `http://proxy-my:KEY@127.0.0.1:1909` — and BrandHawk's
`python scripts/proxy_bridge.py test lazada-my` — use it. Entries here are never auto-pruned and are re-verified every
cycle. One device = one household IP, not a rotating pool: it is good for a country-locked market read slowly, not for
bulk crawling (keep the service's pacing; do not hammer one home connection).

Why this and not a public SOCKS list or a home-grown "bandwidth sharing" network: the owner knows, agreed, and can
turn it off; the traffic is yours, not a stranger's; and the only exposed surface is a password-protected port on a
private network.

## 3. Your own phone/SIM — mobile IP for India

A phone on an Indian SIM with USB tethering or a hotspot gives a **mobile carrier** address (CGNAT, rotates when
airplane mode is toggled). Free if you have the data; slow; only India. Point the machine's connection at it and use
`route=direct`, or run an open-source proxy app on the phone and list it as above with `|IN`.

## 4. Trials of paid services — to test a market, not to run on

Public figures on the Decodo pricing page (checked 2026-10-17): 100 MB for 3 days, and the paid plan **starts
automatically unless you cancel first**. Enough to learn whether a market answers a residential exit at all
(`proxy_bridge.py test <market>` says HELPS or not) before deciding whether any exit is worth building. Do not leave a
card on a trial you do not intend to keep.

## What this will not do

- It does not make a CAPTCHA disappear. Lazada's reCAPTCHA stays; nothing here solves one.
- It does not turn a flaky free pool into a reliable one. For a market that refuses datacenter addresses and has no
  official API, a consented exit in that country (section 2) is the only free route.
