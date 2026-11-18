#!/usr/bin/env python3
"""
subrecon.py — Fully passive subdomain discovery -> aliveness check -> tech/threat triage
Author: 0xSH4N

Stage 1 (PASSIVE ONLY, no packet ever touches the target):
    Pulls subdomains from certificate-transparency logs, passive-DNS databases,
    archive crawls and (if installed) your own CLI tools running in passive mode:
        crt.sh, CertSpotter, AlienVault OTX, HackerTarget, Anubis/jldc.me,
        RapidDNS, Wayback Machine CDX, urlscan.io, BufferOver, ThreatMiner
        + subfinder / amass (-passive) / assetfinder / findomain, IF ON PATH

Stage 2 (active, this is where "alive" gets decided):
    DNS resolve (A/AAAA/CNAME) + HTTP(S) probe every candidate, same way httpx would.

Stage 3 (active, same requests as stage 2 -- no extra traffic unless --deep-probe):
    Tech-stack fingerprinting (headers/cookies/body signatures), subdomain-takeover
    fingerprint matching against dangling CNAMEs, exposed admin/panel detection,
    missing security headers, and a CORS misconfig probe.

Outputs (in -o/--output, default ./subrecon_out):
    alive_subdomains.txt   <- ONLY this: one alive http(s)://host per line, sorted
    raw_subdomains.txt     <- bonus: every candidate found pre-filter (handy for re-runs)
    report.html            <- tech stack + bug-hunting threat triage, open in a browser
    report.json            <- same data, machine-readable

Usage:
    python3 subrecon.py -d example.com
    python3 subrecon.py -d example.com -o out/ -c 60 --use-tools
    python3 subrecon.py -d example.com --vt-key $VT_API_KEY --deep-probe

Optional (never required): set VT_API_KEY / SECURITYTRAILS_API_KEY env vars, or pass
--vt-key / --st-key, to pull two more passive sources that need free API keys.
If subfinder/amass/assetfinder/findomain are on PATH, pass --use-tools to fold them in
(amass is run with -passive, so this stays fully passive even with --use-tools).
"""

import argparse
import asyncio
import json
import os
import re
import shutil
import sys
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

try:
    import aiohttp
except ImportError:
    print("[!] aiohttp is required: pip3 install --break-system-packages aiohttp")
    sys.exit(1)

try:
    import dns.resolver
    import dns.exception
    HAVE_DNS = True
except ImportError:
    HAVE_DNS = False
    print("[!] dnspython not found -> CNAME/takeover checks disabled (pip3 install --break-system-packages dnspython)")

DEFAULT_UA = "Mozilla/5.0 (X11; Linux x86_64) subrecon/1.0 (passive-recon)"
CORS_TEST_ORIGIN = "https://cors-test-evil.example.org"

# ─────────────────────────────── passive sources ────────────────────────────────

SUBDOMAIN_CHAR_RE = r"[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?"

def host_regex_for(domain):
    esc = re.escape(domain)
    return re.compile(rf"(?:{SUBDOMAIN_CHAR_RE}\.)+{esc}", re.I)


class PassiveSources:
    """Each method returns a set[str] of hostnames. Every call is wrapped so a dead
    or rate-limited source never aborts the run -- it just contributes nothing."""

    def __init__(self, session: aiohttp.ClientSession, domain: str, timeout: int, vt_key: str, st_key: str):
        self.session = session
        self.domain = domain
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.vt_key = vt_key
        self.st_key = st_key
        self.hre = host_regex_for(domain)

    async def _get(self, url, headers=None):
        try:
            async with self.session.get(url, timeout=self.timeout, headers=headers or {}) as r:
                if r.status != 200:
                    return None
                return await r.text(errors="ignore")
        except Exception:
            return None

    def _extract(self, text):
        if not text:
            return set()
        return {h.lower().rstrip(".") for h in self.hre.findall(text)}

    async def crtsh(self):
        text = await self._get(f"https://crt.sh/?q=%25.{self.domain}&output=json")
        if not text:
            return set()
        out = set()
        try:
            for row in json.loads(text):
                for field_name in ("name_value", "common_name"):
                    val = row.get(field_name, "")
                    for h in val.split("\n"):
                        h = h.strip().lower().lstrip("*.")
                        if h.endswith(self.domain):
                            out.add(h)
        except Exception:
            out |= self._extract(text)  # malformed JSON, fall back to regex scrape
        return out

    async def certspotter(self):
        text = await self._get(
            f"https://api.certspotter.com/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names"
        )
        if not text:
            return set()
        out = set()
        try:
            for row in json.loads(text):
                for h in row.get("dns_names", []):
                    h = h.lower().lstrip("*.")
                    if h.endswith(self.domain):
                        out.add(h)
        except Exception:
            out |= self._extract(text)
        return out

    async def otx_alienvault(self):
        text = await self._get(f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns")
        if not text:
            return set()
        out = set()
        try:
            for row in json.loads(text).get("passive_dns", []):
                h = row.get("hostname", "").lower().rstrip(".")
                if h.endswith(self.domain):
                    out.add(h)
        except Exception:
            out |= self._extract(text)
        return out

    async def hackertarget(self):
        text = await self._get(f"https://api.hackertarget.com/hostsearch/?q={self.domain}")
        if not text or "error" in text.lower()[:40]:
            return set()
        return self._extract(text)

    async def anubis_jldc(self):
        text = await self._get(f"https://jldc.me/anubis/subdomains/{self.domain}")
        if not text:
            return set()
        out = set()
        try:
            for h in json.loads(text):
                h = h.lower().rstrip(".")
                if h.endswith(self.domain):
                    out.add(h)
        except Exception:
            out |= self._extract(text)
        return out

    async def rapiddns(self):
        text = await self._get(f"https://rapiddns.io/subdomain/{self.domain}?full=1#result")
        return self._extract(text)

    async def wayback_cdx(self):
        text = await self._get(
            f"https://web.archive.org/cdx/search/cdx?url=*.{self.domain}&output=json&collapse=urlkey&fl=original&limit=20000"
        )
        if not text:
            return set()
        out = set()
        try:
            rows = json.loads(text)
            for row in rows[1:]:  # first row is the header
                url = row[0] if row else ""
                host = urlsplit(url if "//" in url else "//" + url).netloc.lower()
                if host.endswith(self.domain):
                    out.add(host)
        except Exception:
            out |= self._extract(text)
        return out

    async def urlscan(self):
        text = await self._get(f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}&size=10000")
        if not text:
            return set()
        out = set()
        try:
            for row in json.loads(text).get("results", []):
                h = (row.get("page", {}) or {}).get("domain", "")
                if h and h.lower().endswith(self.domain):
                    out.add(h.lower())
        except Exception:
            out |= self._extract(text)
        return out

    async def bufferover(self):
        text = await self._get(f"https://dns.bufferover.run/dns?q=.{self.domain}")
        return self._extract(text)

    async def threatminer(self):
        text = await self._get(f"https://api.threatminer.org/v2/domain.php?q={self.domain}&rt=5")
        if not text:
            return set()
        out = set()
        try:
            for h in json.loads(text).get("results", []):
                h = h.lower().rstrip(".")
                if h.endswith(self.domain):
                    out.add(h)
        except Exception:
            out |= self._extract(text)
        return out

    async def virustotal(self):
        if not self.vt_key:
            return set()
        text = await self._get(
            f"https://www.virustotal.com/api/v3/domains/{self.domain}/subdomains?limit=1000",
            headers={"x-apikey": self.vt_key},
        )
        if not text:
            return set()
        out = set()
        try:
            for row in json.loads(text).get("data", []):
                h = row.get("id", "").lower()
                if h.endswith(self.domain):
                    out.add(h)
        except Exception:
            pass
        return out

    async def securitytrails(self):
        if not self.st_key:
            return set()
        text = await self._get(
            f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains",
            headers={"APIKEY": self.st_key},
        )
        if not text:
            return set()
        out = set()
        try:
            for sub in json.loads(text).get("subdomains", []):
                out.add(f"{sub}.{self.domain}".lower())
        except Exception:
            pass
        return out

    async def run_all(self):
        jobs = [
            self.crtsh(), self.certspotter(), self.otx_alienvault(), self.hackertarget(),
            self.anubis_jldc(), self.rapiddns(), self.wayback_cdx(), self.urlscan(),
            self.bufferover(), self.threatminer(), self.virustotal(), self.securitytrails(),
        ]
        names = [
            "crt.sh", "CertSpotter", "AlienVault OTX", "HackerTarget", "Anubis/jldc.me",
            "RapidDNS", "Wayback CDX", "urlscan.io", "BufferOver", "ThreatMiner",
            "VirusTotal", "SecurityTrails",
        ]
        results = await asyncio.gather(*jobs, return_exceptions=True)
        merged = set()
        for name, res in zip(names, results):
            if isinstance(res, Exception) or res is None:
                print(f"    [source] {name:16s}: 0 (unreachable/error)")
                continue
            print(f"    [source] {name:16s}: {len(res)}")
            merged |= res
        return merged


async def run_external_tools(domain, use_tools, ext_timeout):
    """Opportunistic CLI tool fold-in. amass runs -passive so nothing active happens here."""
    if not use_tools:
        return set()
    tools = {
        "subfinder": ["subfinder", "-d", domain, "-all", "-silent"],
        "amass": ["amass", "enum", "-passive", "-d", domain],
        "assetfinder": ["assetfinder", "--subs-only", domain],
        "findomain": ["findomain", "-t", domain, "-q"],
    }
    merged = set()
    hre = host_regex_for(domain)
    for name, cmd in tools.items():
        path = shutil.which(cmd[0])
        if not path:
            continue
        print(f"    [tool]   {name:16s}: running...")
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
            )
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=ext_timeout)
            found = {h.lower().rstrip(".") for h in hre.findall(out.decode(errors="ignore"))}
            print(f"    [tool]   {name:16s}: {len(found)}")
            merged |= found
        except Exception as e:
            print(f"    [tool]   {name:16s}: failed ({e})")
    return merged


def sanitize_subdomains(raw: set, domain: str) -> set:
    out = set()
    for h in raw:
        h = h.strip().lower().lstrip("*.").rstrip(".")
        if ":" in h:  # strip stray ports
            h = h.split(":")[0]
        if not h or " " in h or "@" in h:
            continue
        if h == domain or h.endswith("." + domain):
            out.add(h)
    return out


# ─────────────────────────────── DNS + takeover fingerprints ────────────────────────────────

# subset of the well-known "can-i-take-over-xyz" dangling-CNAME signatures
TAKEOVER_FINGERPRINTS = [
    ("github.io", "GitHub Pages", re.compile(r"there isn't a github pages site here", re.I)),
    ("herokuapp.com", "Heroku", re.compile(r"no such app", re.I)),
    ("herokudns.com", "Heroku", re.compile(r"no such app", re.I)),
    ("s3.amazonaws.com", "AWS S3", re.compile(r"nosuchbucket|the specified bucket does not exist", re.I)),
    ("s3-website", "AWS S3 (website)", re.compile(r"nosuchbucket|the specified bucket does not exist", re.I)),
    ("azurewebsites.net", "Azure App Service", re.compile(r"404 web site not found", re.I)),
    ("cloudapp.net", "Azure Cloud Service", None),
    ("trafficmanager.net", "Azure Traffic Manager", None),
    ("blob.core.windows.net", "Azure Blob Storage", re.compile(r"blobnotfound", re.I)),
    ("fastly.net", "Fastly", re.compile(r"fastly error: unknown domain", re.I)),
    ("myshopify.com", "Shopify", re.compile(r"sorry, this shop is currently unavailable", re.I)),
    ("unbouncepages.com", "Unbounce", re.compile(r"the requested url was not found on this server", re.I)),
    ("wordpress.com", "WordPress.com", re.compile(r"do you want to register", re.I)),
    ("tumblr.com", "Tumblr", re.compile(r"there's nothing here", re.I)),
    ("zendesk.com", "Zendesk", re.compile(r"help center closed", re.I)),
    ("statuspage.io", "Statuspage", re.compile(r"you are being .*redirected|this page could not be found", re.I)),
    ("surge.sh", "Surge.sh", re.compile(r"project not found", re.I)),
    ("bitbucket.io", "Bitbucket Pages", re.compile(r"repository not found", re.I)),
    ("wpengine.com", "WP Engine", None),
    ("pantheonsite.io", "Pantheon", re.compile(r"404 error unknown site", re.I)),
    ("helpscoutdocs.com", "Help Scout", re.compile(r"no settings were found", re.I)),
    ("ghost.io", "Ghost", re.compile(r"the thing you were looking for is no longer here", re.I)),
    ("webflow.io", "Webflow", re.compile(r"the page you are looking for doesn't exist", re.I)),
    ("teamwork.com", "Teamwork", re.compile(r"oops - we didn't find that page", re.I)),
    ("uservoice.com", "UserVoice", re.compile(r"this uservoice subdomain is currently available", re.I)),
    ("intercom.help", "Intercom", re.compile(r"this help center does not exist", re.I)),
    ("readme.io", "ReadMe.io", re.compile(r"project doesnt exist.*readme|this domain isn.?t configured", re.I)),
    ("desk.com", "Desk.com", re.compile(r"please try again or try desk\.com", re.I)),
    ("campaignmonitor.com", "Campaign Monitor", re.compile(r"trying to access your account", re.I)),
    ("ngrok.io", "ngrok tunnel", None),
    ("netlify.app", "Netlify", re.compile(r"not found - request id", re.I)),
    ("vercel.app", "Vercel", re.compile(r"the deployment could not be found|dns_hostname_empty", re.I)),
]

# lightweight tech fingerprints: header/cookie/body signature -> tech name
TECH_SIGNATURES = [
    ("header", "Server", re.compile(r"nginx", re.I), "Nginx"),
    ("header", "Server", re.compile(r"apache", re.I), "Apache"),
    ("header", "Server", re.compile(r"microsoft-iis", re.I), "IIS"),
    ("header", "Server", re.compile(r"cloudflare", re.I), "Cloudflare"),
    ("header", "Server", re.compile(r"openresty", re.I), "OpenResty"),
    ("header", "X-Powered-By", re.compile(r"php", re.I), "PHP"),
    ("header", "X-Powered-By", re.compile(r"asp\.net", re.I), "ASP.NET"),
    ("header", "X-Powered-By", re.compile(r"express", re.I), "Express.js"),
    ("header", "Via", re.compile(r"varnish", re.I), "Varnish"),
    ("cookie", None, re.compile(r"^PHPSESSID$", re.I), "PHP"),
    ("cookie", None, re.compile(r"^JSESSIONID$", re.I), "Java"),
    ("cookie", None, re.compile(r"^laravel_session$", re.I), "Laravel"),
    ("cookie", None, re.compile(r"^(csrftoken|sessionid)$", re.I), "Django"),
    ("cookie", None, re.compile(r"^ci_session$", re.I), "CodeIgniter"),
    ("cookie", None, re.compile(r"^connect\.sid$", re.I), "Express.js"),
    ("body", None, re.compile(r"wp-content|wp-includes", re.I), "WordPress"),
    ("body", None, re.compile(r"/sites/default/files|Drupal\.settings", re.I), "Drupal"),
    ("body", None, re.compile(r"Joomla!", re.I), "Joomla"),
    ("body", None, re.compile(r"cdn\.shopify\.com|Shopify\.theme", re.I), "Shopify"),
    ("body", None, re.compile(r"__NEXT_DATA__", re.I), "Next.js"),
    ("body", None, re.compile(r"ng-version=", re.I), "Angular"),
    ("body", None, re.compile(r'id="react-root"|data-reactroot', re.I), "React"),
    ("body", None, re.compile(r"__NUXT__", re.I), "Nuxt.js"),
    ("body", None, re.compile(r"csrf-token.*content=.*laravel|Laravel", re.I), "Laravel"),
    ("body", None, re.compile(r"django", re.I), "Django"),
    ("body", None, re.compile(r"<meta name=\"generator\" content=\"([^\"]+)\"", re.I), None),  # handled specially
]

# exposed admin/panel keyword -> (service name, severity)
PANEL_SIGNATURES = [
    (re.compile(r"jenkins", re.I), "Jenkins", "high"),
    (re.compile(r"grafana", re.I), "Grafana", "medium"),
    (re.compile(r"kibana", re.I), "Kibana", "medium"),
    (re.compile(r"phpmyadmin", re.I), "phpMyAdmin", "high"),
    (re.compile(r"pgadmin", re.I), "pgAdmin", "high"),
    (re.compile(r"adminer", re.I), "Adminer", "high"),
    (re.compile(r"rabbitmq management", re.I), "RabbitMQ Management", "high"),
    (re.compile(r"swagger-ui|swagger ui", re.I), "Swagger UI", "medium"),
    (re.compile(r"graphiql|graphql playground", re.I), "GraphQL Playground", "medium"),
    (re.compile(r"portainer", re.I), "Portainer", "high"),
    (re.compile(r"gitlab", re.I), "GitLab", "medium"),
    (re.compile(r"<title>\s*jira", re.I), "Jira", "medium"),
    (re.compile(r"confluence", re.I), "Confluence", "medium"),
    (re.compile(r"zabbix", re.I), "Zabbix", "medium"),
    (re.compile(r"kubernetes dashboard", re.I), "Kubernetes Dashboard", "critical"),
    (re.compile(r"minio", re.I), "MinIO Console", "high"),
    (re.compile(r"prometheus time series collection", re.I), "Prometheus", "medium"),
    (re.compile(r"cpanel", re.I), "cPanel", "medium"),
    (re.compile(r"plesk", re.I), "Plesk", "medium"),
    (re.compile(r"outlook web app|owa", re.I), "Outlook Web Access", "medium"),
    (re.compile(r"vmware vsphere|vcenter", re.I), "vCenter", "high"),
    (re.compile(r"citrix", re.I), "Citrix Gateway", "medium"),
]

SECURITY_HEADERS = [
    "Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options",
    "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy",
]

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class HostResult:
    host: str
    alive: bool = False
    scheme: str = ""
    final_url: str = ""
    status: int = 0
    title: str = ""
    server: str = ""
    tech: list = field(default_factory=list)
    cname: str = ""
    resolved_ips: list = field(default_factory=list)
    dns_status: str = ""  # resolved / nxdomain / timeout / no_cname
    takeover: dict = None   # {"service":..., "confidence":..., "evidence":...}
    panels: list = field(default_factory=list)   # [{"service","severity"}]
    cors_issue: dict = None
    missing_sec_headers: list = field(default_factory=list)
    threats: list = field(default_factory=list)  # [{"severity","summary"}]


# ─────────────────────────────── DNS resolution ────────────────────────────────

def resolve_one(host, resolver):
    """Sync, called via executor. Returns (cname, ips, dns_status)."""
    cname = ""
    ips = []
    status = "resolved"
    try:
        answer = resolver.resolve(host, "CNAME")
        cname = str(answer[0].target).rstrip(".")
    except Exception:
        pass
    try:
        answer = resolver.resolve(host, "A")
        ips = [r.to_text() for r in answer]
    except dns.resolver.NXDOMAIN:
        status = "nxdomain"
    except dns.resolver.NoAnswer:
        if not cname:
            status = "no_a_record"
    except dns.exception.Timeout:
        status = "timeout"
    except Exception:
        status = "error"
    if cname and not ips and status == "resolved":
        status = "cname_only"
    return cname, ips, status


async def resolve_all(hosts, concurrency, resolve_timeout):
    if not HAVE_DNS:
        return {h: ("", [], "dns_unavailable") for h in hosts}
    resolver = dns.resolver.Resolver()
    resolver.timeout = resolve_timeout
    resolver.lifetime = resolve_timeout
    loop = asyncio.get_event_loop()
    sem = asyncio.Semaphore(concurrency)
    results = {}

    async def _one(h):
        async with sem:
            cname, ips, status = await loop.run_in_executor(None, resolve_one, h, resolver)
            results[h] = (cname, ips, status)

    await asyncio.gather(*[_one(h) for h in hosts])
    return results


def check_takeover(cname, dns_status, body):
    if not cname:
        return None
    for suffix, service, fingerprint in TAKEOVER_FINGERPRINTS:
        if suffix in cname.lower():
            if dns_status == "nxdomain":
                return {"service": service, "confidence": "high",
                        "evidence": f"CNAME -> {cname} (NXDOMAIN, classic dangling CNAME)"}
            if fingerprint and body and fingerprint.search(body):
                return {"service": service, "confidence": "high",
                        "evidence": f"CNAME -> {cname}, response body matches '{service}' unclaimed fingerprint"}
            if dns_status in ("cname_only", "no_a_record"):
                return {"service": service, "confidence": "medium",
                        "evidence": f"CNAME -> {cname} resolves but no A record -- verify manually"}
            return {"service": service, "confidence": "low",
                    "evidence": f"CNAME -> {cname} matches a known takeover-prone service -- review manually"}
    return None


# ─────────────────────────────── HTTP probing + fingerprinting ────────────────────────────────

class Prober:
    def __init__(self, timeout, concurrency, check_cors):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.sem = asyncio.Semaphore(concurrency)
        self.check_cors = check_cors

    async def probe(self, session, host) -> HostResult:
        res = HostResult(host=host)
        async with self.sem:
            for scheme in ("https", "http"):
                url = f"{scheme}://{host}/"
                try:
                    async with session.get(url, timeout=self.timeout, allow_redirects=True,
                                            headers={"User-Agent": DEFAULT_UA}) as r:
                        body = await r.text(errors="ignore")
                        res.alive = True
                        res.scheme = scheme
                        res.final_url = str(r.url)
                        res.status = r.status
                        res.server = r.headers.get("Server", "")
                        m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
                        res.title = re.sub(r"\s+", " ", m.group(1)).strip()[:120] if m else ""
                        self._fingerprint_tech(res, r.headers, r.cookies, body)
                        self._fingerprint_panels(res, res.title, body)
                        self._check_missing_headers(res, r.headers)
                        if self.check_cors:
                            await self._check_cors(session, url, res)
                        res.extra_body_for_takeover = body[:5000]
                        break
                except Exception:
                    continue
        return res

    def _fingerprint_tech(self, res, headers, cookies, body):
        found = set()
        for kind, key, pat, techname in TECH_SIGNATURES:
            if kind == "header" and key in headers and pat.search(headers.get(key, "")):
                found.add(techname)
            elif kind == "cookie":
                for ck in cookies.keys():
                    if pat.search(ck):
                        found.add(techname)
            elif kind == "body" and techname and pat.search(body or ""):
                found.add(techname)
        m = re.search(r'<meta name="generator" content="([^"]+)"', body or "", re.I)
        if m:
            found.add(m.group(1).strip()[:60])
        res.tech = sorted(found)

    def _fingerprint_panels(self, res, title, body):
        hay = f"{title}\n{(body or '')[:3000]}"
        for pat, service, sev in PANEL_SIGNATURES:
            if pat.search(hay):
                res.panels.append({"service": service, "severity": sev})
                res.threats.append({"severity": sev, "summary": f"Exposed {service} instance detected"})

    def _check_missing_headers(self, res, headers):
        missing = [h for h in SECURITY_HEADERS if h not in headers]
        res.missing_sec_headers = missing

    async def _check_cors(self, session, url, res):
        try:
            async with session.get(url, timeout=self.timeout,
                                    headers={"User-Agent": DEFAULT_UA, "Origin": CORS_TEST_ORIGIN}) as r:
                aco = r.headers.get("Access-Control-Allow-Origin", "")
                acc = r.headers.get("Access-Control-Allow-Credentials", "")
                if aco == CORS_TEST_ORIGIN:
                    sev = "high" if acc.lower() == "true" else "medium"
                    res.cors_issue = {"severity": sev, "evidence": f"ACAO reflects arbitrary Origin ({aco}), ACAC={acc}"}
                    res.threats.append({"severity": sev, "summary": f"CORS misconfig: reflects attacker Origin, credentials={acc or 'false'}"})
                elif aco == "*":
                    res.cors_issue = {"severity": "low", "evidence": "Access-Control-Allow-Origin: * (wildcard)"}
                    res.threats.append({"severity": "low", "summary": "CORS wildcard (Access-Control-Allow-Origin: *)"})
        except Exception:
            pass


# ─────────────────────────────── output writers ────────────────────────────────

def write_outputs(out_dir, domain, raw_subs, host_results: dict, elapsed, sources_used):
    os.makedirs(out_dir, exist_ok=True)

    with open(os.path.join(out_dir, "raw_subdomains.txt"), "w") as fh:
        for h in sorted(raw_subs):
            fh.write(h + "\n")

    alive = [r for r in host_results.values() if r.alive]
    alive.sort(key=lambda r: r.host)
    with open(os.path.join(out_dir, "alive_subdomains.txt"), "w") as fh:
        for r in alive:
            fh.write(f"{r.scheme}://{r.host}\n")

    takeovers = [r for r in host_results.values() if r.takeover]
    panels = [r for r in alive if r.panels]
    cors_issues = [r for r in alive if r.cors_issue]

    report = {
        "domain": domain,
        "elapsed_seconds": round(elapsed, 1),
        "sources_used": sources_used,
        "counts": {
            "raw_candidates": len(raw_subs),
            "alive": len(alive),
            "takeover_candidates": len(takeovers),
            "exposed_panels": len(panels),
            "cors_issues": len(cors_issues),
        },
        "hosts": [
            {
                "host": r.host, "alive": r.alive, "scheme": r.scheme, "status": r.status,
                "title": r.title, "server": r.server, "tech": r.tech, "cname": r.cname,
                "resolved_ips": r.resolved_ips, "dns_status": r.dns_status,
                "takeover": r.takeover, "panels": r.panels, "cors_issue": r.cors_issue,
                "missing_security_headers": r.missing_sec_headers,
                "threats": r.threats,
            }
            for r in sorted(host_results.values(), key=lambda x: x.host)
        ],
    }
    with open(os.path.join(out_dir, "report.json"), "w") as fh:
        json.dump(report, fh, indent=2)

    write_html_report(out_dir, report)
    return report


def write_html_report(out_dir, report):
    def esc(s):
        return (str(s) if s is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    def sev_badge(sev):
        return f"<span class='badge {esc(sev)}'>{esc(sev).upper()}</span>"

    rows = []
    for h in report["hosts"]:
        if not h["alive"] and not h["takeover"]:
            continue  # dead hosts with no takeover signal add no value to the report
        threats_html = ""
        all_threats = list(h["threats"])
        if h["takeover"]:
            all_threats.insert(0, {"severity": "critical" if h["takeover"]["confidence"] == "high" else "medium",
                                    "summary": f"Possible subdomain takeover ({h['takeover']['service']}): {h['takeover']['evidence']}"})
        all_threats.sort(key=lambda t: SEV_ORDER.get(t["severity"], 5))
        for t in all_threats:
            threats_html += f"<div>{sev_badge(t['severity'])} {esc(t['summary'])}</div>"
        if not threats_html and h["missing_security_headers"]:
            threats_html = f"<div class='muted'>Missing headers: {esc(', '.join(h['missing_security_headers']))}</div>"
        elif h["missing_security_headers"]:
            threats_html += f"<div class='muted'>Missing headers: {esc(', '.join(h['missing_security_headers']))}</div>"

        top_sev = min((SEV_ORDER.get(t["severity"], 5) for t in all_threats), default=5)
        row_class = {0: "critical", 1: "high", 2: "medium", 3: "low"}.get(top_sev, "")

        status_badge = h["status"] if h["alive"] else "DEAD/DNS-ONLY"
        rows.append((top_sev, f"""
        <tr class="{row_class}">
          <td><code>{esc(h['host'])}</code>{f"<br><a href='{esc(h['scheme']+'://'+h['host'])}' target='_blank' class='muted'>open ↗</a>" if h['alive'] else ''}</td>
          <td>{esc(status_badge)}</td>
          <td>{esc(h['title'])}</td>
          <td>{esc(', '.join(h['tech']) or '-')}{f"<br><span class='muted'>{esc(h['server'])}</span>" if h['server'] else ''}</td>
          <td>{esc(h['cname']) or '-'}</td>
          <td>{threats_html or '<span class="muted">none observed</span>'}</td>
        </tr>"""))
    rows.sort(key=lambda x: x[0])
    rows_html = "\n".join(r[1] for r in rows)

    c = report["counts"]
    sources_html = "".join(f"<li>{esc(s)}</li>" for s in report["sources_used"])

    html = f"""<!doctype html><html><head><meta charset="utf-8"><title>subrecon: {esc(report['domain'])}</title>
<style>
body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#0b0e14;color:#dce1e8;margin:2rem}}
h1{{color:#fff;margin-bottom:0}} .sub{{color:#8893a7;margin-top:.2rem}}
table{{width:100%;border-collapse:collapse;font-size:13px;margin-top:1rem}}
td,th{{border:1px solid #232834;padding:8px 10px;text-align:left;vertical-align:top}}
th{{background:#161a24;position:sticky;top:0}} code{{color:#9ecbff;word-break:break-all}}
tr.critical{{background:#3a1414}} tr.high{{background:#3a2414}} tr.medium{{background:#33321a}} tr.low{{background:#15222b}}
.summary{{display:flex;gap:1rem;margin:1rem 0;flex-wrap:wrap}}
.card{{background:#161a24;padding:1rem 1.2rem;border-radius:8px;min-width:130px}}
.card b{{font-size:1.6rem;display:block}}
.badge{{display:inline-block;padding:1px 7px;border-radius:10px;font-size:10px;font-weight:700;margin-right:4px}}
.badge.critical{{background:#ff4d4d;color:#1a0000}} .badge.high{{background:#ff9f43;color:#2a1400}}
.badge.medium{{background:#ffd43b;color:#2a2400}} .badge.low{{background:#51cf66;color:#002a08}}
.badge.info{{background:#4dabf7;color:#001a2a}}
.muted{{color:#8893a7;font-size:12px}} a{{color:#9ecbff}}
details{{background:#161a24;padding:.6rem 1rem;border-radius:8px;margin-top:.5rem}}
</style></head><body>
<h1>subrecon</h1>
<p class="sub">target: <b>{esc(report['domain'])}</b> &middot; passive enumeration + active alive/tech/threat triage &middot; {report['elapsed_seconds']}s</p>
<div class="summary">
<div class="card"><b>{c['raw_candidates']}</b>candidates found</div>
<div class="card"><b>{c['alive']}</b>alive</div>
<div class="card"><b>{c['takeover_candidates']}</b>takeover candidates</div>
<div class="card"><b>{c['exposed_panels']}</b>exposed panels</div>
<div class="card"><b>{c['cors_issues']}</b>CORS issues</div>
</div>
<details><summary>Passive sources queried</summary><ul>{sources_html}</ul></details>
<table>
<tr><th>Host</th><th>Status</th><th>Title</th><th>Tech / Server</th><th>CNAME</th><th>Threats for bug hunting</th></tr>
{rows_html}
</table>
<p class="muted" style="margin-top:2rem">
Takeover and panel findings are heuristic fingerprint matches — confirm manually before reporting.
Rows for dead hosts are omitted unless a takeover signal was found on them (that's the classic case: service is gone, CNAME isn't).
</p>
</body></html>"""
    with open(os.path.join(out_dir, "report.html"), "w") as fh:
        fh.write(html)


# ─────────────────────────────── orchestration ────────────────────────────────

async def main_async(args):
    domain = args.domain.lower().strip().lstrip("*.").rstrip(".")
    os.makedirs(args.output, exist_ok=True)
    t0 = time.monotonic()

    vt_key = args.vt_key or os.environ.get("VT_API_KEY", "")
    st_key = args.st_key or os.environ.get("SECURITYTRAILS_API_KEY", "")

    connector = aiohttp.TCPConnector(limit=args.concurrency, ssl=False)
    async with aiohttp.ClientSession(connector=connector, headers={"User-Agent": DEFAULT_UA}) as session:
        print(f"[*] Stage 1/3: passive subdomain discovery for {domain}")
        sources = PassiveSources(session, domain, args.source_timeout, vt_key, st_key)
        passive_found = await sources.run_all()
        tool_found = await run_external_tools(domain, args.use_tools, args.ext_timeout)
        raw = sanitize_subdomains(passive_found | tool_found | {domain}, domain)
        print(f"[*] Total unique candidates after dedupe/sanitize: {len(raw)}")

        sources_used = [
            "crt.sh", "CertSpotter", "AlienVault OTX", "HackerTarget", "Anubis/jldc.me",
            "RapidDNS", "Wayback Machine CDX", "urlscan.io", "BufferOver", "ThreatMiner",
        ]
        if vt_key:
            sources_used.append("VirusTotal")
        if st_key:
            sources_used.append("SecurityTrails")
        if args.use_tools:
            sources_used.append("local tools (subfinder/amass -passive/assetfinder/findomain, if installed)")

        print(f"[*] Stage 2/3: DNS resolution ({len(raw)} hosts)")
        dns_results = await resolve_all(raw, args.dns_concurrency, args.resolve_timeout)

        print(f"[*] Stage 2/3: HTTP probing ({len(raw)} hosts)")
        prober = Prober(args.timeout, args.concurrency, not args.skip_cors)
        host_results = {}
        probe_tasks = [prober.probe(session, h) for h in raw]
        probed = await asyncio.gather(*probe_tasks)
        for r in probed:
            cname, ips, dns_status = dns_results.get(r.host, ("", [], ""))
            r.cname = cname
            r.resolved_ips = ips
            r.dns_status = dns_status
            body_for_takeover = getattr(r, "extra_body_for_takeover", "")
            r.takeover = check_takeover(cname, dns_status, body_for_takeover)
            host_results[r.host] = r

        # also run takeover check for hosts that never got an HTTP response at all
        # (they still got resolved/attempted in dns_results if present in raw)
        for h in raw:
            if h not in host_results:
                cname, ips, dns_status = dns_results.get(h, ("", [], ""))
                hr = HostResult(host=h, alive=False, cname=cname, resolved_ips=ips, dns_status=dns_status)
                hr.takeover = check_takeover(cname, dns_status, "")
                host_results[h] = hr

    elapsed = time.monotonic() - t0
    print("[*] Stage 3/3: writing reports")
    report = write_outputs(args.output, domain, raw, host_results, elapsed, sources_used)

    print("\n" + "=" * 60)
    print(f"Done in {elapsed:.1f}s.")
    for k, v in report["counts"].items():
        print(f"  {k:20s}: {v}")
    print(f"\nOutput dir: {os.path.abspath(args.output)}")
    print(f"  - alive_subdomains.txt  (ONLY alive hosts, feed this into katana/nuclei/etc)")
    print(f"  - report.html           (tech stack + bug-hunting threat triage, open in a browser)")
    print(f"  - report.json / raw_subdomains.txt")
    if not HAVE_DNS:
        print("\n[!] dnspython wasn't installed, so CNAME/takeover checks were skipped this run.")


def build_argparser():
    p = argparse.ArgumentParser(description="Fully passive subdomain discovery + alive/tech/threat triage")
    p.add_argument("-d", "--domain", required=True, help="target domain, e.g. example.com")
    p.add_argument("-o", "--output", default="subrecon_out", help="output directory")
    p.add_argument("-c", "--concurrency", type=int, default=50, help="HTTP probe concurrency")
    p.add_argument("--dns-concurrency", type=int, default=50)
    p.add_argument("--timeout", type=int, default=10, help="per-HTTP-request timeout (s)")
    p.add_argument("--resolve-timeout", type=float, default=5.0, help="per-DNS-query timeout (s)")
    p.add_argument("--source-timeout", type=int, default=20, help="per passive-source HTTP timeout (s)")
    p.add_argument("--ext-timeout", type=int, default=180, help="timeout for each external CLI tool (s)")
    p.add_argument("--use-tools", action="store_true",
                    help="also fold in subfinder/amass(-passive)/assetfinder/findomain if installed")
    p.add_argument("--vt-key", default="", help="VirusTotal API key (optional; or set VT_API_KEY env var)")
    p.add_argument("--st-key", default="", help="SecurityTrails API key (optional; or set SECURITYTRAILS_API_KEY env var)")
    p.add_argument("--skip-cors", action="store_true", help="skip the CORS misconfig probe")
    p.add_argument("--deep-probe", action="store_true", help="reserved for future common-path checks (currently no-op)")
    return p


def main():
    args = build_argparser().parse_args()
    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(130)


if __name__ == "__main__":
    main()
