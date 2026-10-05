import httpx

from headerscope import checks
from headerscope.cli import main
from headerscope.report import html_report
from headerscope.scanner import TLSInfo, analyze, check_tls, scan

STRONG = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "Content-Security-Policy": "default-src 'self'; script-src 'self' 'nonce-abc' 'strict-dynamic'; object-src 'none'; "
                               "base-uri 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Server": "nginx",
}


def ids(findings, status):
    return {f.id for f in findings if f.status == status}


def test_hsts_variants():
    assert checks.check_hsts({}, True)[0].status == "fail"
    assert checks.check_hsts({"strict-transport-security": "max-age=300"}, True)[0].status == "warn"
    assert checks.check_hsts(STRONG, True)[0].status == "pass"
    assert checks.check_hsts(STRONG, False)[0].penalty == 20


def test_csp_weaknesses():
    weak = checks.check_csp({"Content-Security-Policy": "default-src * 'unsafe-inline' 'unsafe-eval'"})[0]
    assert weak.status == "warn" and "unsafe-inline" in weak.detail and "unsafe-eval" in weak.detail
    assert checks.check_csp(STRONG)[0].status == "pass"
    assert checks.check_csp({"Content-Security-Policy-Report-Only": "default-src 'self'"})[0].status == "fail"
    # unsafe-inline is ignored by browsers when a nonce is present -> not penalised
    assert "unsafe-inline" not in checks.check_csp(
        {"Content-Security-Policy": "script-src 'self' 'nonce-x' 'unsafe-inline'; object-src 'none'; base-uri 'none'"})[0].detail


def test_framing():
    assert checks.check_framing({"X-Frame-Options": "DENY"})[0].status == "pass"
    assert checks.check_framing({})[0].status == "fail"


def test_disclosure():
    f = checks.check_disclosure({"Server": "Apache/2.4.29 (Ubuntu)", "X-Powered-By": "PHP/7.2.1"})[0]
    assert f.status == "warn" and "PHP/7.2.1" in f.detail
    assert checks.check_disclosure({"Server": "nginx"})[0].status == "pass"


def test_cors():
    assert checks.check_cors({"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"})[0].status == "fail"
    assert checks.check_cors({"Access-Control-Allow-Origin": "null"})[0].status == "fail"
    assert checks.check_cors({"Access-Control-Allow-Origin": "*"})[0].status == "info"


def test_cookies():
    out = checks.check_cookies(["sessionid=abc; Path=/", "theme=dark; Secure; HttpOnly; SameSite=Lax"], True)
    by_name = {f.title: f for f in out}
    assert by_name["Cookie 'sessionid'"].status == "fail" and "Secure" in by_name["Cookie 'sessionid'"].detail
    assert by_name["Cookie 'theme'"].status == "pass"


def test_grades():
    assert [checks.grade(s) for s in (100, 90, 80, 70, 55, 40, 10)] == ["A+", "A", "B", "C", "D", "E", "F"]


def test_tls_findings():
    ok = TLSInfo("TLSv1.3", "TLS_AES_256_GCM_SHA384", "Let's Encrypt", "2027-01-01", 200)
    assert all(f.status == "pass" for f in check_tls(ok, None))
    old = TLSInfo("TLSv1", "x", "y", "2020-01-01", -5)
    assert {f.id for f in check_tls(old, None) if f.status == "fail"} == {"tls_version", "tls_expiry"}
    assert check_tls(None, "certificate verification failed")[0].penalty == 25


def test_strong_site_scores_a_plus():
    r = analyze("https://x", STRONG, ["sid=1; Secure; HttpOnly; SameSite=Strict"], 200, "https://x/", [], True)
    assert r.grade == "A+" and not ids(r.findings, "fail")


def test_weak_site_scores_f():
    r = analyze("http://x", {"Server": "Apache/2.2.15", "X-Powered-By": "PHP/5.4"}, ["PHPSESSID=1; path=/"],
                200, "http://x/", [], None)
    assert r.grade == "F"
    assert {"hsts", "csp", "clickjacking", "nosniff"} <= ids(r.findings, "fail")


def mock_http():
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.scheme == "http":
            return httpx.Response(301, headers={"Location": str(req.url.copy_with(scheme="https"))})
        return httpx.Response(200, headers={**STRONG, "Set-Cookie": "sid=1; Secure; HttpOnly; SameSite=Lax"}, text="ok")
    return httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True)


def test_scan_with_mock_transport():
    r = scan("example.test", client=mock_http(), check_tls_cert=False)
    assert r.final_url == "https://example.test" and r.grade == "A+"
    assert any(f.id == "https_redirect" and f.status == "pass" for f in r.findings)


def test_cli_and_html(tmp_path, capsys):
    out = tmp_path / "r.html"
    code = main(["example.test", "--no-tls", "--html", str(out), "--min-grade", "A"], client=mock_http())
    assert code == 0 and "<table>" in out.read_text(encoding="utf-8")
    assert "Grade A+" in capsys.readouterr().out
    assert "<script>" not in html_report([])
