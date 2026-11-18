# Recon/Triage Toolkit — subrecon · vulnscan · logicscan

Three standalone Python tools that chain into one pipeline: find subdomains, triage
them for active vulnerabilities, then dig into specific endpoints for logic/functional
bugs. Each tool also works completely on its own.

```
subrecon.py          logicscan.py
  (passive recon)       (headless logic/auth/BOLA testing)
      |                        ^
      v                        |
alive_subdomains.txt --> vulnscan.py --> feed interesting
      |                  (active XSS/SQLi/           endpoints back
      |                   redirect/JS-secret          into logicscan
      v                   scan)
  katana -list ...
```

**For authorized testing only** — your own bug bounty scope, or an engagement you're
contracted for. All three tools are built for that use case (the BB/PT mode in
`logicscan.py`, the BB-scope-exclusion framing, etc.) and assume you already have
permission to test the target.

---

## 1. Setup

All three are single files, no packaging needed.

```bash
pip3 install --break-system-packages aiohttp requests dnspython playwright PyJWT
playwright install chromium   # only needed for logicscan.py
```

Optional, auto-detected if present on `PATH` (never required):

| Tool | Looks for |
|---|---|
| `vulnscan.py` | `httpx`, `dalfox`, `sqlmap`, `gf`, `qsreplace`, `subjs`, `nuclei` |
| `subrecon.py` | `subfinder`, `amass` (run with `-passive`), `assetfinder`, `findomain` |
| `logicscan.py` | none — pure Python + Playwright |

If a tool isn't installed, the script just skips that source/augmentation and keeps
going on its built-in logic.

---

## 2. `subrecon.py` — passive subdomain discovery → alive check → tech/threat triage

```bash
python3 subrecon.py -d example.com -o out/
python3 subrecon.py -d example.com --use-tools -t 60     # fold in subfinder/amass -passive/etc
```

**Stage 1 (fully passive)** — pulls from crt.sh, CertSpotter, AlienVault OTX, HackerTarget,
Anubis/jldc.me, RapidDNS, Wayback Machine CDX, urlscan.io, BufferOver, ThreatMiner, plus
optional VirusTotal/SecurityTrails if you pass `--vt-key`/`--st-key` (or set `VT_API_KEY`/
`SECURITYTRAILS_API_KEY`). `--use-tools` adds subfinder/amass(`-passive`)/assetfinder/
findomain if they're on `PATH` — amass is forced passive, so this stays fully passive.

**Stage 2 (active)** — DNS resolves (A/CNAME) and HTTP(S) probes every candidate, same
idea as `httpx`.

**Stage 3 (active, same requests)** — tech-stack fingerprinting, subdomain-takeover
fingerprint matching against dangling CNAMEs (~30 services: S3, Heroku, Azure, Fastly,
GitHub Pages, Netlify, Vercel, Shopify, etc.), exposed admin/panel detection (Jenkins,
Grafana, Kibana, phpMyAdmin, Kubernetes Dashboard...), missing security headers, CORS
misconfig probe.

**Outputs** (`-o out/`):
- `alive_subdomains.txt` — only the alive hosts, as `scheme://host`, feeds straight
  into `katana -list alive_subdomains.txt -o urls.txt`
- `report.html` — tech stack + severity-sorted threat table per host
- `report.json`, `raw_subdomains.txt`

Key flags: `-c/--concurrency`, `--dns-concurrency`, `--skip-cors`, `--vt-key`/`--st-key`.

---

## 3. `vulnscan.py` — active XSS / SQLi / open-redirect / JS-secret scan

Sits right after `katana`:

```bash
katana -list alive_subdomains.txt -o urls.txt
python3 vulnscan.py -i urls.txt -o results/
```

- **JS enumeration** — fetches every `.js` URL, extracts embedded endpoints
  (LinkFinder-style regex) and flags secrets (AWS/GCP keys, JWTs, Slack webhooks,
  generic `api_key=` assigns).
- **XSS** — canary-token reflection probe, then escalates with context-breaking
  payloads (`"><script>`, `'><svg/onload=`, etc.) to confirm unescaped reflection
  rather than just flagging encoded reflection.
- **SQLi** — error-based (DB fingerprint regex: MySQL/Postgres/MSSQL/Oracle/SQLite),
  boolean-based (`OR 1=1` vs `AND 1=2` response-length diffing against a baseline),
  optional time-based with `--time-based` (off by default — slow/noisy).
- **Open redirect** — tests redirect-looking params against off-site payloads,
  checks both `Location` header and client-side meta/JS redirects.
- Optional deeper confirmation via `--use-dalfox` / `--use-sqlmap` if those are
  installed (capped, never required).

**Outputs** (`-o results/`): `report.html` (severity-sorted table), `report.json`,
plus flat `xss.txt` / `sqli.txt` / `openredirect.txt` / `js_secrets.txt` /
`js_endpoints.txt`.

Key flags: `-c/--concurrency`, `--timeout`, `--header "Cookie: ..."` for authenticated
scans, `--skip-xss`/`--skip-sqli`/`--skip-redirect` to narrow scope.

---

## 4. `logicscan.py` — headless crawl + logic/functional vulnerability triage

```bash
python3 logicscan.py -u https://example.com/auth/sign_in --mode bb
python3 logicscan.py -u https://example.com/dashboard --cookie "session=abc123" --mode pt
python3 logicscan.py -l seeds.txt --cookie "session=abc" --cookie2 "session=def" -t 6
```

Point it at a specific endpoint instead of a whole site. Real headless Chromium
(Playwright) renders the page, submits/discovers forms, and captures every XHR/fetch
call with full headers and bodies — not just the static HTML. Each seed URL runs
concurrently in its own thread with its own browser instance (`-t/--threads`).

**Unauthenticated / login endpoints** (`/auth/sign_in`-style): detects login forms and
tests NoSQL operator injection (`$ne`/`$gt`/`$regex`, both JSON-body and
bracket-notation form fields for Express/qs-style parsers) and classic SQLi bypass,
comparing against a real baseline-failure response. Also flags missing CSRF tokens.

**Authenticated endpoints** (`/dashboard`-style — the cookie-parsing feature):
`--cookie`/`--cookie-file` accepts a raw header string (paste from devtools), a JSON
cookie list, or a Playwright `storage_state.json`. With a session supplied, it:
- discovers parameterized API calls from the JS-driven crawl and tests **BOLA/IDOR**
  via same-session ID tampering, plus a zero-cookie control request to catch broken
  auth; `--cookie2` (a second, different account's cookies) upgrades a BOLA lead into
  a **confirmed cross-account** finding
- decodes any JWT found and, only against endpoints actually observed sending it as
  `Authorization: Bearer ...`, replays a forged `alg=none` token with a no-header
  control to check for signature-verification bypass
- scans for exposed `.env`/`.git`/source maps, secrets/PII, GraphQL introspection,
  CORS reflection, missing security headers, session cookie flags, reflected Host
  header, and flags multi-field JSON writes as mass-assignment candidates

**Modes**:
- `--mode bb` (default) — HTML report sections findings into *Likely IN SCOPE* /
  *VARIES — check program policy* / *Likely OUT OF SCOPE*, based on common
  HackerH1/Bugcrowd exclusion patterns (e.g. missing-headers-alone and standalone
  clickjacking land in "out of scope"; auth bypass and BOLA land in "in scope").
- `--mode pt` — full technical severity, no scope filtering, for pentest reporting.

**Outputs** (`-o logicscan_out/`): `report.html`, `report.json`.

Key flags: `--depth`/`--max-pages` (keep shallow — this targets a specific endpoint,
not a full-site spider), `--skip-auth-bypass`/`--skip-jwt`/`--skip-bola`/
`--skip-info-disclosure`/`--skip-headers` to narrow scope, `--no-headless` for
debugging.

**Caveat worth repeating**: logic/functional bugs are judgment calls by nature.
Every finding is a heuristic lead with evidence, not a confirmed vulnerability —
verify manually before including it in a report.

---

## 5. Suggested end-to-end flow

```bash
# 1. Passive recon -> alive hosts + first-pass threat read
python3 subrecon.py -d target.com -o recon/ --use-tools

# 2. Active crawl + injection/XSS/redirect sweep across everything alive
katana -list recon/alive_subdomains.txt -o recon/urls.txt
python3 vulnscan.py -i recon/urls.txt -o vulnscan_out/

# 3. Deep-dive specific interesting endpoints (auth pages, dashboards found above)
python3 logicscan.py \
  -u https://app.target.com/auth/sign_in \
  -u https://app.target.com/dashboard \
  --cookie "session=<your authorized test session>" \
  --mode bb -o logicscan_out/
```

---

## 6. Honest limitations

- **Sandbox-tested, not internet-tested here.** All three were validated against
  local mock servers (a deliberately vulnerable login+dashboard app, a fake CT-log/
  passive-DNS response set, etc.) because this environment's network is locked to a
  package-registry allowlist. They have not been run against a real target by me —
  run them against a scope you control first to sanity-check behavior.
- **Heuristics, not ground truth.** BOLA detection relies on response-structure
  similarity; boolean-based SQLi relies on response-length diffing; takeover
  detection relies on known CNAME-suffix fingerprints. All three can produce false
  positives/negatives on unusual apps — treat every finding as a lead.
- **Be mindful of request volume.** None of these are rate-limited by default beyond
  the concurrency flags. On login endpoints especially, keep `-c`/`-t` conservative
  if the target has lockout policies.
