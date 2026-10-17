"""Free proxy list sources used by the harvester (Proxy-api.py, Live-proxies.py, Proxy-harvester.py).

When a list dies or moves, edit only this file. A running service picks the change up on its next
collect cycle, with no restart.

* Put # in front of a line to switch a list off, or move it to DEAD_SOURCES.
* A bare "ip:port" entry in a list whose URL names socks5 / socks4 (.../socks5.txt, protocol=socks4) is
  tested as that protocol; entries that carry their own scheme (socks5://ip:port) keep it.
* JSON APIs work too (Geonode style: objects with ip, port, protocols, country).
* Find dead or empty lists with:  venv\\Scripts\\python app.py sources
"""

SOURCES = [
    # --- Mixed / HTTP lists ---
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.txt",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt",
    "https://raw.githubusercontent.com/theriturajps/proxy-list/main/proxies.txt",
    "https://raw.githubusercontent.com/komutan234/Proxy-List-Free/main/proxies/http.txt",
    "https://raw.githubusercontent.com/iplocate/free-proxy-list/main/all-proxies.txt",
    "https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/http.txt",
    "https://cdn.jsdelivr.net/gh/databay-labs/free-proxy-list/http.txt",
    "https://raw.githubusercontent.com/zloi-user/hideip.me/main/http.txt",
    "https://raw.githubusercontent.com/zloi-user/hideip.me/main/https.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/all.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
    "https://api.proxyscrape.com/v2/?request=get&protocol=http&timeout=5000&country=all&ssl=all&anonymity=all",
    "https://www.proxy-list.download/api/v1/get?type=http",
    "https://api.openproxylist.xyz/http.txt",
    "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
    "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
    "https://raw.githubusercontent.com/shiftytr/proxy-list/master/proxy.txt",
    "https://raw.githubusercontent.com/Thordata/awesome-free-proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/prxchk/proxy-list/main/http.txt",
    "https://raw.githubusercontent.com/databay-labs/free-proxy-list/master/http.txt",
    "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/http.txt",
    "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/https.txt",
    "https://raw.githubusercontent.com/zevtyardt/proxy-list/main/http.txt",
    "https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt",
    "https://raw.githubusercontent.com/elliottophellia/yakumo/master/results/http/global/http_checked.txt",
    "https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/http_proxies.txt",
    "https://raw.githubusercontent.com/casals-ar/proxy-list/main/http",
    "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/main/All_proxies.txt",
    "https://raw.githubusercontent.com/r00tee/Proxy-List/main/Https.txt",
    "https://raw.githubusercontent.com/Vann-Dev/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/claude89757/free_https_proxies/main/https_proxies.txt",

    # --- Fresh / high-update lists (every 5-30 min) ---
    "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/http.txt",
    "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/https.txt",
    "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/http.txt",
    "https://raw.githubusercontent.com/TuanMinPay/live-proxy/master/http.txt",
    "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/http.txt",
    "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/https.txt",
    "https://raw.githubusercontent.com/ProxyScraper/ProxyScraper/main/http.txt",
    "https://raw.githubusercontent.com/proxylist-to/proxy-list/main/http.txt",
    "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies_anonymous/http.txt",
    "https://raw.githubusercontent.com/ObcbO/getproxy/master/file/http.txt",
    "https://raw.githubusercontent.com/hanwayTech/free-proxy-list/main/http.txt",
    "https://raw.githubusercontent.com/hanwayTech/free-proxy-list/main/https.txt",
    "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/generated/http_proxies.txt",
    "https://raw.githubusercontent.com/B4RC0DE-TM/proxy-list/main/HTTP.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/http.txt",
    "https://raw.githubusercontent.com/andigwandi/free-proxy/main/proxy_list.txt",
    "https://raw.githubusercontent.com/im-razvan/proxy_list/main/http.txt",

    # --- ProxyScrape API ---
    "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=http&timeout=10000&country=all&anonymity=all",
    "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=socks5&timeout=10000",
    "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=socks4&timeout=10000",
    "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_format=protocolipport&format=text",

    # --- JSON APIs ---
    "https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc&filterUpTime=90&protocols=http",
    "https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc&filterUpTime=90&protocols=socks5",

    # --- SOCKS5 lists ---
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt",
    "https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/socks5.txt",
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/zevtyardt/proxy-list/main/socks5.txt",
    "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/socks5.txt",
    "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/socks5.txt",
    "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/socks5.txt",
    "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/ObcbO/getproxy/master/file/socks5.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
    "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/generated/socks5_proxies.txt",
    "https://raw.githubusercontent.com/B4RC0DE-TM/proxy-list/main/SOCKS5.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/socks5.txt",
    "https://raw.githubusercontent.com/im-razvan/proxy_list/main/socks5.txt",
    "https://raw.githubusercontent.com/prxchk/proxy-list/main/socks5.txt",
    "https://raw.githubusercontent.com/elliottophellia/yakumo/master/results/socks5/global/socks5_checked.txt",
    "https://raw.githubusercontent.com/ProxyList-to/proxy-list/main/socks5.txt",
    "https://raw.githubusercontent.com/zloi-user/hideip.me/main/socks5.txt",
    "https://raw.githubusercontent.com/r00tee/Proxy-List/main/Socks5.txt",

    # --- SOCKS4 lists ---
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks4/data.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",
    "https://raw.githubusercontent.com/zevtyardt/proxy-list/main/socks4.txt",
    "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/socks4.txt",
    "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/socks4.txt",
    "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/socks4.txt",
    "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/socks4.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4_RAW.txt",
    "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/generated/socks4_proxies.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/socks4.txt",
    "https://raw.githubusercontent.com/prxchk/proxy-list/main/socks4.txt",
    "https://raw.githubusercontent.com/elliottophellia/yakumo/master/results/socks4/global/socks4_checked.txt",
    "https://raw.githubusercontent.com/ProxyList-to/proxy-list/main/socks4.txt",
    "https://raw.githubusercontent.com/zloi-user/hideip.me/main/socks4.txt",
]

# {cc} = lower-case ISO-2, {CC} = upper-case ISO-2. Each template is expanded once per country code in
# PROXY_SERVICE_COUNTRY_SOURCES, and every proxy it returns is tagged with that country.
COUNTRY_SOURCE_TEMPLATES = [
    "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&country={cc}&proxy_format=protocolipport&format=text",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/countries/{CC}/data.txt",
]

# Returned 404 on 2026-10-17. Not fetched; move a URL back into SOURCES to use it again.
DEAD_SOURCES = [
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all.txt",  # moved to proxies/all/data.txt
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/http.txt",  # moved to proxies/protocols/http/data.txt
    "https://raw.githubusercontent.com/iplocate/free-proxy-list/main/http.txt",  # moved to protocols/http.txt
    "https://raw.githubusercontent.com/gitrecon1455/fresh-proxy-list/main/all.txt",
    "https://raw.githubusercontent.com/gfpcom/free-proxy-list/main/http.txt",
    "https://raw.githubusercontent.com/gfpcom/free-proxy-list/main/https.txt",
    "https://raw.githubusercontent.com/saschazesiger/Free-Proxies/master/proxies/http.txt",
    "https://raw.githubusercontent.com/mertguvencli/http-proxy-list/main/proxy-list/data.txt",
    "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/http/http.txt",
    "https://raw.githubusercontent.com/rxvl-d/ProxyList/main/results.txt",
    "https://raw.githubusercontent.com/UptimerBot/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/rx443/proxy-list/online/online/http.txt",
    "https://raw.githubusercontent.com/HyperBeats/proxy-list/main/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies_anonymous/http.txt",
    "https://raw.githubusercontent.com/zevtyardt/proxy-list/main/https.txt",
    "https://raw.githubusercontent.com/yemixzy/proxy-list/main/proxies/unchecked.txt",
    "https://raw.githubusercontent.com/caliphdev/Proxy-List/master/http.txt",
    "https://raw.githubusercontent.com/caliphdev/Proxy-List/master/socks5.txt",
]
