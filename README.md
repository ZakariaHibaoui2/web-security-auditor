# HeaderScope — Web Security Posture Auditor

> One command grades any website from **A+ to F** on its browser-side defences. It checks the HTTPS redirect, HSTS, a deep Content-Security-Policy analysis, clickjacking and MIME-sniffing protection, cookie flags, CORS misconfigurations, version banners, and the TLS protocol and certificate, and it gives a copy-paste fix for every problem.

[![CI](https://github.com/ZakariaHibaoui2/web-security-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/ZakariaHibaoui2/web-security-auditor/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)
![httpx](https://img.shields.io/badge/httpx-HTTP%2F1.1%20%26%202-blue)
![OWASP](https://img.shields.io/badge/OWASP-Secure%20Headers-black)
![License](https://img.shields.io/badge/license-MIT-green)

---

## Demo (live scan, October 2026)

```text
$ headerscope github.com example.com wikipedia.org --html report.html

https://github.com  ->  https://github.com  [200]
Grade A+   score 96/100
  WARN  Permissions-Policy                   -2  missing
  WARN  Cookie '_octo'                       -2  missing HttpOnly
  PASS  HTTP -> HTTPS redirect                   http:// redirects to https://
  PASS  Strict-Transport-Security                max-age=31536000, includeSubDomains, preload
  PASS  Content-Security-Policy                  enforced policy without obvious weaknesses
  PASS  TLS protocol                             TLSv1.3 (TLS_AES_128_GCM_SHA256)
  ...

https://example.com  ->  https://example.com  [200]
Grade E   score 35/100
  FAIL  Content-Security-Policy             -20  missing - no defence-in-depth against XSS
        fix: Start with: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'
  FAIL  Strict-Transport-Security           -15  missing - downgrade/SSL-strip possible
  FAIL  HTTP -> HTTPS redirect              -10  http:// stays on HTTP
  ...

https://wikipedia.org  ->  https://www.wikipedia.org/  [200]
Grade D   score 57/100
  FAIL  Content-Security-Policy             -20  missing - no defence-in-depth against XSS
  WARN  Technology / version disclosure      -3  Server: ATS/9.2.15
  ...
```

Results reflect each site's configuration at scan time. The scan sends ordinary GET requests (the URL and its `http://` variant) plus one TLS handshake: no fuzzing, no payloads.

## Checks

| Area | What is verified | Max penalty |
|---|---|---|
| Transport | HTTP → HTTPS redirect; HSTS present, `max-age` ≥ 6 months, `includeSubDomains`/`preload` advice | 10 / 20 |
| TLS | negotiated protocol (TLS < 1.2 fails), certificate validity, issuer, days to expiry (< 14 days warns) | 15 / 30 |
| CSP | enforced vs report-only; `'unsafe-inline'` (ignored if nonce/hash/`strict-dynamic`), `'unsafe-eval'`, wildcard/scheme sources, `object-src`, `base-uri` | 20 |
| Clickjacking | `frame-ancestors` or `X-Frame-Options: DENY/SAMEORIGIN` | 10 |
| Hardening headers | `X-Content-Type-Options: nosniff`, `Referrer-Policy` (flags `unsafe-url`), `Permissions-Policy`, COOP | 5 / 3 / 2 |
| Cookies | `Secure`, `HttpOnly`, `SameSite`, `SameSite=None` without `Secure`; session/auth cookies weigh more | per cookie |
| CORS | `*` with credentials, `null` origin | 15 |
| Disclosure | `Server` with version, `X-Powered-By`, `X-AspNet-Version`, `X-Generator` | 3 each |

Score = 100 − penalties → **A+ ≥ 95, A ≥ 85, B ≥ 75, C ≥ 65, D ≥ 50, E ≥ 35, F**.

## Usage

```bash
pip install -e ".[dev]"
headerscope example.com                              # text report
headerscope site1.com site2.com --html audit.html    # self-contained HTML report
headerscope https://staging.myapp.com --json
headerscope myapp.com --min-grade B                  # CI gate: exit 1 below B
```

```python
from headerscope.scanner import scan
r = scan("myapp.com")
print(r.grade, r.score, [f.title for f in r.findings if f.status == "fail"])
```

## Project structure

```
src/headerscope/
├── checks.py    # pure header/cookie/CSP analysis + grading (fully unit-tested)
├── scanner.py   # httpx fetch, redirect chain, http->https check, TLS inspection
├── report.py    # text + HTML (escaped) reports
└── cli.py
tests/           # 12 offline tests (httpx MockTransport): every check, grading extremes, scan flow, CLI/HTML
```

> Only audit sites you own or are authorised to assess.

## License

[MIT](LICENSE)
