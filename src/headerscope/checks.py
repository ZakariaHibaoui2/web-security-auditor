"""Pure analysis functions: HTTP response headers -> findings (no network here)."""
from __future__ import annotations

import re
from dataclasses import dataclass
from http.cookies import SimpleCookie


@dataclass
class Finding:
    id: str
    title: str
    status: str        # pass | warn | fail | info
    penalty: int       # points removed from 100
    detail: str = ""
    fix: str = ""


def _h(headers: dict[str, str], name: str) -> str | None:
    for k, v in headers.items():
        if k.lower() == name.lower():
            return v
    return None


def check_hsts(headers: dict, is_https: bool) -> list[Finding]:
    if not is_https:
        return [Finding("hsts", "Strict-Transport-Security", "fail", 20, "site not served over HTTPS",
                        "Serve the site over HTTPS and redirect all HTTP traffic.")]
    v = _h(headers, "Strict-Transport-Security")
    fix = "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
    if not v:
        return [Finding("hsts", "Strict-Transport-Security", "fail", 15, "missing - downgrade/SSL-strip possible", fix)]
    m = re.search(r"max-age\s*=\s*\"?(\d+)", v, re.I)
    age = int(m.group(1)) if m else 0
    if age < 15_552_000:   # 180 days
        return [Finding("hsts", "Strict-Transport-Security", "warn", 8, f"max-age={age} is shorter than 6 months", fix)]
    extras = [x for x in ("includeSubDomains", "preload") if x.lower() not in v.lower()]
    if extras:
        return [Finding("hsts", "Strict-Transport-Security", "pass", 0, f"max-age={age}; consider {', '.join(extras)}")]
    return [Finding("hsts", "Strict-Transport-Security", "pass", 0, f"max-age={age}, includeSubDomains, preload")]


def parse_csp(policy: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for part in policy.split(";"):
        tokens = part.strip().split()
        if tokens:
            out.setdefault(tokens[0].lower(), [t for t in tokens[1:]])
    return out


def check_csp(headers: dict) -> list[Finding]:
    v = _h(headers, "Content-Security-Policy")
    if not v:
        ro = _h(headers, "Content-Security-Policy-Report-Only")
        detail = "only Report-Only policy present (not enforced)" if ro else "missing - no defence-in-depth against XSS"
        return [Finding("csp", "Content-Security-Policy", "fail", 20, detail,
                        "Start with: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'")]
    d = parse_csp(v)
    issues, penalty = [], 0
    script = d.get("script-src", d.get("default-src", []))
    if not script and "default-src" not in d:
        issues.append("no script-src/default-src (scripts unrestricted)")
        penalty += 10
    nonce_or_hash = any(t.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for t in script)
    if "'unsafe-inline'" in script and not nonce_or_hash and "'strict-dynamic'" not in script:
        issues.append("'unsafe-inline' scripts allowed")
        penalty += 10
    if "'unsafe-eval'" in script:
        issues.append("'unsafe-eval' allowed")
        penalty += 5
    if any(t in {"*", "http:", "https:", "data:"} for t in script):
        issues.append("script-src allows wildcard / any scheme")
        penalty += 10
    if "object-src" not in d and "'none'" not in d.get("default-src", []):
        issues.append("object-src not restricted")
        penalty += 3
    if "base-uri" not in d:
        issues.append("base-uri missing (base-tag injection)")
        penalty += 2
    if not issues:
        return [Finding("csp", "Content-Security-Policy", "pass", 0, "enforced policy without obvious weaknesses")]
    return [Finding("csp", "Content-Security-Policy", "warn", min(penalty, 18), "; ".join(issues),
                    "Use nonces/hashes with 'strict-dynamic' instead of 'unsafe-inline'; avoid 'unsafe-eval'.")]


def check_framing(headers: dict) -> list[Finding]:
    xfo = _h(headers, "X-Frame-Options")
    csp = parse_csp(_h(headers, "Content-Security-Policy") or "")
    if "frame-ancestors" in csp or (xfo and xfo.strip().upper() in {"DENY", "SAMEORIGIN"}):
        return [Finding("clickjacking", "Clickjacking protection", "pass", 0, "frame-ancestors / X-Frame-Options set")]
    return [Finding("clickjacking", "Clickjacking protection", "fail", 10, "page can be framed by any site",
                    "Content-Security-Policy: frame-ancestors 'self'   (or X-Frame-Options: DENY)")]


def check_simple(headers: dict) -> list[Finding]:
    out = []
    xcto = _h(headers, "X-Content-Type-Options")
    out.append(Finding("nosniff", "X-Content-Type-Options", "pass" if (xcto or "").lower() == "nosniff" else "fail",
                       0 if (xcto or "").lower() == "nosniff" else 5, xcto or "missing",
                       "X-Content-Type-Options: nosniff"))
    rp = (_h(headers, "Referrer-Policy") or "").lower()
    weak = rp in {"unsafe-url", "no-referrer-when-downgrade"}
    out.append(Finding("referrer", "Referrer-Policy", "pass" if rp and not weak else "warn", 0 if rp and not weak else 3,
                       rp or "missing (browser default)", "Referrer-Policy: strict-origin-when-cross-origin"))
    pp = _h(headers, "Permissions-Policy")
    out.append(Finding("permissions", "Permissions-Policy", "pass" if pp else "warn", 0 if pp else 2,
                       "set" if pp else "missing", "Permissions-Policy: camera=(), microphone=(), geolocation=()"))
    coop = _h(headers, "Cross-Origin-Opener-Policy")
    out.append(Finding("coop", "Cross-Origin-Opener-Policy", "pass" if coop else "info", 0, coop or "not set",
                       "Cross-Origin-Opener-Policy: same-origin"))
    return out


VERSION_RE = re.compile(r"\d+\.\d+")


def check_disclosure(headers: dict) -> list[Finding]:
    leaks = []
    for name in ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator"):
        v = _h(headers, name)
        if v and (name != "Server" or VERSION_RE.search(v)):
            leaks.append(f"{name}: {v}")
    if leaks:
        return [Finding("disclosure", "Technology / version disclosure", "warn", 3 * len(leaks), "; ".join(leaks),
                        "Remove version banners (server_tokens off; expose_php = Off; app.disable('x-powered-by')).")]
    return [Finding("disclosure", "Technology / version disclosure", "pass", 0, "no version banners")]


def check_cors(headers: dict) -> list[Finding]:
    acao = _h(headers, "Access-Control-Allow-Origin")
    creds = (_h(headers, "Access-Control-Allow-Credentials") or "").lower() == "true"
    if acao == "*" and creds:
        return [Finding("cors", "CORS", "fail", 15, "wildcard origin with credentials", "Reflect an allow-list instead.")]
    if acao == "null":
        return [Finding("cors", "CORS", "fail", 10, "origin 'null' allowed (sandboxed iframes can read responses)",
                        "Never allow the 'null' origin.")]
    if acao == "*":
        return [Finding("cors", "CORS", "info", 0, "public resource (wildcard, no credentials)")]
    return [Finding("cors", "CORS", "pass", 0, f"Access-Control-Allow-Origin: {acao}" if acao else "not enabled")]


def check_cookies(set_cookie_headers: list[str], is_https: bool) -> list[Finding]:
    out = []
    for raw in set_cookie_headers:
        c = SimpleCookie()
        try:
            c.load(raw)
        except Exception:  # noqa: BLE001 - malformed cookies are reported, not fatal
            out.append(Finding("cookie", "Cookie", "warn", 2, f"unparseable Set-Cookie: {raw[:60]}"))
            continue
        lower = raw.lower()
        for name in c:
            missing = []
            if is_https and "secure" not in lower:
                missing.append("Secure")
            if "httponly" not in lower:
                missing.append("HttpOnly")
            if "samesite" not in lower:
                missing.append("SameSite")
            if "samesite=none" in lower and "secure" not in lower:
                missing.append("Secure (required with SameSite=None)")
            sensitive = re.search(r"(sess|auth|token|sid|jwt|login|remember)", name, re.I)
            if missing:
                out.append(Finding("cookie", f"Cookie '{name}'", "fail" if sensitive else "warn",
                                   (5 if sensitive else 2) * len(missing), "missing " + ", ".join(missing),
                                   f"Set-Cookie: {name}=...; Secure; HttpOnly; SameSite=Lax"))
            else:
                out.append(Finding("cookie", f"Cookie '{name}'", "pass", 0, "Secure; HttpOnly; SameSite"))
    return out


def grade(score: int) -> str:
    for g, t in (("A+", 95), ("A", 85), ("B", 75), ("C", 65), ("D", 50), ("E", 35)):
        if score >= t:
            return g
    return "F"
