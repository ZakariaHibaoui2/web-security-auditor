"""Text and self-contained HTML reports."""
from __future__ import annotations

import html

from .scanner import Report

ICON = {"pass": "PASS", "warn": "WARN", "fail": "FAIL", "info": "INFO"}
COLOR = {"pass": "#1a7f37", "warn": "#9a6700", "fail": "#cf222e", "info": "#57606a"}


def text(r: Report) -> str:
    lines = [f"{r.url}  ->  {r.final_url}  [{r.status}]",
             f"Grade {r.grade}   score {r.score}/100", ""]
    for f in sorted(r.findings, key=lambda x: ({"fail": 0, "warn": 1, "info": 2, "pass": 3}[x.status], -x.penalty)):
        pen = f"-{f.penalty}" if f.penalty else ""
        lines.append(f"  {ICON[f.status]}  {f.title:<34}{pen:>5}  {f.detail}")
        if f.status in {"fail", "warn"} and f.fix:
            lines.append(f"  {'':>4}  {'fix:':>34}{'':>5}  {f.fix}")
    return "\n".join(lines)


def html_report(reports: list[Report]) -> str:
    cards = []
    for r in reports:
        rows = "".join(
            f"<tr><td style='color:{COLOR[f.status]};font-weight:600'>{ICON[f.status]}</td>"
            f"<td>{html.escape(f.title)}</td><td>{html.escape(f.detail)}</td>"
            f"<td><code>{html.escape(f.fix) if f.status in ('fail', 'warn') else ''}</code></td></tr>"
            for f in r.findings)
        cards.append(f"""<section><h2>{html.escape(r.final_url)}
<span class="grade g{r.grade[0]}">{r.grade}</span><small>{r.score}/100</small></h2>
<table><thead><tr><th></th><th>Check</th><th>Result</th><th>Recommended fix</th></tr></thead>
<tbody>{rows}</tbody></table></section>""")
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Web Security Audit</title>
<style>
body{{font-family:system-ui,sans-serif;margin:0;padding:24px;background:#f6f8fa;color:#1f2328}}
section{{background:#fff;border:1px solid #d0d7de;border-radius:10px;padding:16px 20px;margin:0 auto 20px;max-width:1100px}}
h2{{font-size:18px;display:flex;gap:12px;align-items:center;word-break:break-all}} small{{color:#57606a;font-weight:400}}
.grade{{border-radius:8px;padding:2px 12px;color:#fff;font-size:20px}} .gA{{background:#1a7f37}} .gB{{background:#4c9a2a}}
.gC{{background:#9a6700}} .gD,.gE{{background:#bc4c00}} .gF{{background:#cf222e}}
table{{border-collapse:collapse;width:100%;font-size:14px}} td,th{{border-top:1px solid #d0d7de;padding:8px;text-align:left;vertical-align:top}}
code{{font-size:12px;white-space:pre-wrap}}
</style></head><body><h1 style="max-width:1100px;margin:0 auto 16px">Web Security Audit</h1>{''.join(cards)}</body></html>"""
