"""Network side: fetch a URL (and its http:// variant), inspect TLS, run every check."""
from __future__ import annotations

import socket
import ssl
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from urllib.parse import urlsplit, urlunsplit

import httpx

from . import __version__, checks
from .checks import Finding

UA = f"headerscope/{__version__} (+https://github.com/ZakariaHibaoui2/web-security-auditor)"


@dataclass
class TLSInfo:
    version: str
    cipher: str
    issuer: str
    expires: str
    days_left: int


@dataclass
class Report:
    url: str
    final_url: str
    status: int
    score: int
    grade: str
    redirect_chain: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    tls: TLSInfo | None = None

    def as_dict(self) -> dict:
        return asdict(self)


def tls_info(host: str, port: int = 443, timeout: float = 8.0) -> TLSInfo:
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock, ctx.wrap_socket(sock, server_hostname=host) as s:
        cert = s.getpeercert()
        expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
        issuer = dict(x[0] for x in cert["issuer"]).get("organizationName", "?")
        return TLSInfo(s.version() or "?", s.cipher()[0], issuer, expires.date().isoformat(),
                       (expires - datetime.now(UTC)).days)


def check_tls(info: TLSInfo | None, error: str | None) -> list[Finding]:
    if error:
        return [Finding("tls", "TLS certificate", "fail", 25, error, "Install a valid certificate (e.g. Let's Encrypt).")]
    if info is None:
        return []
    out = []
    if info.version in {"TLSv1", "TLSv1.1", "SSLv3"}:
        out.append(Finding("tls_version", "TLS protocol", "fail", 15, f"{info.version} negotiated", "Disable TLS < 1.2."))
    else:
        out.append(Finding("tls_version", "TLS protocol", "pass", 0, f"{info.version} ({info.cipher})"))
    if info.days_left < 0:
        out.append(Finding("tls_expiry", "Certificate validity", "fail", 30, f"expired on {info.expires}"))
    elif info.days_left < 14:
        out.append(Finding("tls_expiry", "Certificate validity", "warn", 5, f"expires in {info.days_left} days",
                           "Automate renewal (certbot / ACME)."))
    else:
        out.append(Finding("tls_expiry", "Certificate validity", "pass", 0,
                           f"{info.issuer}, valid until {info.expires} ({info.days_left} days)"))
    return out


def analyze(url: str, headers: dict[str, str], set_cookies: list[str], status: int, final_url: str,
            chain: list[str], http_redirects_to_https: bool | None, tls: TLSInfo | None = None,
            tls_error: str | None = None) -> Report:
    is_https = final_url.startswith("https://")
    findings: list[Finding] = []
    if http_redirects_to_https is not None:
        findings.append(Finding("https_redirect", "HTTP -> HTTPS redirect", "pass" if http_redirects_to_https else "fail",
                                0 if http_redirects_to_https else 10,
                                "http:// redirects to https://" if http_redirects_to_https else "http:// stays on HTTP",
                                "Redirect all HTTP requests with a 301 to HTTPS."))
    findings += checks.check_hsts(headers, is_https)
    findings += checks.check_csp(headers)
    findings += checks.check_framing(headers)
    findings += checks.check_simple(headers)
    findings += checks.check_disclosure(headers)
    findings += checks.check_cors(headers)
    findings += checks.check_cookies(set_cookies, is_https)
    findings += check_tls(tls, tls_error)
    score = max(0, 100 - sum(f.penalty for f in findings))
    return Report(url, final_url, status, score, checks.grade(score), chain, findings, tls)


def scan(url: str, client: httpx.Client | None = None, check_tls_cert: bool = True) -> Report:
    if "://" not in url:
        url = "https://" + url
    http = client or httpx.Client(timeout=15, follow_redirects=True, headers={"User-Agent": UA})
    resp = http.get(url)
    chain = [str(r.url) for r in resp.history] + [str(resp.url)]
    headers = {k: v for k, v in resp.headers.items() if k.lower() != "set-cookie"}
    cookies = resp.headers.get_list("set-cookie")

    parts = urlsplit(str(resp.url))
    redirect_ok = None
    if parts.scheme == "https":
        try:
            plain = http.get(urlunsplit(("http", parts.netloc, parts.path or "/", "", "")))
            redirect_ok = str(plain.url).startswith("https://")
        except httpx.HTTPError:
            redirect_ok = None   # port 80 closed is acceptable

    tls, tls_error = None, None
    if check_tls_cert and parts.scheme == "https":
        try:
            tls = tls_info(parts.hostname or "", parts.port or 443)
        except ssl.SSLCertVerificationError as exc:
            tls_error = f"certificate verification failed: {exc.verify_message}"
        except OSError as exc:
            tls_error = f"TLS connection failed: {exc}"
    return analyze(url, headers, cookies, resp.status_code, str(resp.url), chain, redirect_ok, tls, tls_error)
