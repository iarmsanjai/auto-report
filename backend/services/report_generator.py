"""
Report Generator — renders HTML reports using Jinja2 templates.
Supports multiple templates (default_report, modern_report).
"""
from __future__ import annotations

import html as html_mod
import logging
from datetime import datetime
from pathlib import Path
from typing import List

import bleach
import markdown2
from markupsafe import Markup
from jinja2 import Environment, FileSystemLoader, select_autoescape

from config.settings import settings
from models.schemas import Finding, FindingStats, ReportMeta

log = logging.getLogger(__name__)

SEV_COLORS = {
    "critical": ("#e60000", "#ffffff"),
    "high":     ("#ff7a00", "#ffffff"),
    "medium":   ("#ffcc00", "#000000"),
    "low":      ("#6b1c4f", "#ffffff"),
    "info":     ("#6e6e6e", "#ffffff"),
}

EASE_COLORS = {
    "Trivial":   ("#196b24", "#ffffff"),
    "Moderate":  ("#ff7a00", "#ffffff"),
    "Difficult": ("#c00000", "#ffffff"),
}

ALLOWED_TAGS = list(bleach.sanitizer.ALLOWED_TAGS) + [
    "p", "h1", "h2", "h3", "h4", "pre", "code", "table",
    "thead", "tbody", "tr", "th", "td", "img", "br", "hr",
    "ul", "ol", "li", "blockquote", "strong", "em",
]


def _render_md(text: str) -> str:
    if not text:
        return ""
    raw = markdown2.markdown(
        text,
        extras=["fenced-code-blocks", "tables", "strike", "code-friendly"],
    )
    cleaned = bleach.clean(raw, tags=ALLOWED_TAGS, strip=True)
    return Markup(cleaned)


def _fmt_date(d: str, long: bool = True) -> str:
    if not d:
        return ""
    try:
        dt = datetime.fromisoformat(d.strip())
        if long:
            return f"{dt.day} {dt.strftime('%B %Y')}"
        return f"{dt.day:02d}-{dt.month:02d}-{dt.year}"
    except Exception:
        return d


def compute_stats(findings: List[Finding]) -> FindingStats:
    active = [f for f in findings if not f.false_positive]
    return FindingStats(
        count_critical=sum(1 for f in active if f.cvss.level == "critical"),
        count_high=sum(1 for f in active if f.cvss.level == "high"),
        count_medium=sum(1 for f in active if f.cvss.level == "medium"),
        count_low=sum(1 for f in active if f.cvss.level == "low"),
        count_info=sum(1 for f in active if f.cvss.level == "info"),
        total=len(active),
    )


def _build_env() -> Environment:
    """Build Jinja2 environment with templates dir and custom filters."""
    env = Environment(
        loader=FileSystemLoader(str(settings.TEMPLATES_DIR)),
        autoescape=select_autoescape(["html"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["md"] = _render_md
    env.filters["fmt_date"] = _fmt_date
    env.filters["fmt_date_short"] = lambda d: _fmt_date(d, long=False)
    env.filters["capitalize"] = lambda s: str(s or "").capitalize()
    env.filters["sev_color"] = lambda s: SEV_COLORS.get(s, ("#6e6e6e", "#ffffff"))[0]
    env.filters["sev_text"] = lambda s: SEV_COLORS.get(s, ("#6e6e6e", "#ffffff"))[1]
    env.filters["ease_color"] = lambda s: EASE_COLORS.get(s, ("#ff7a00", "#ffffff"))[0]
    env.filters["ease_text"] = lambda s: EASE_COLORS.get(s, ("#ff7a00", "#ffffff"))[1]
    return env


def render_report(
    meta: ReportMeta,
    findings: List[Finding],
    template_name: str = "default_report",
) -> str:
    """Render an HTML report using the specified template."""
    stats = compute_stats(findings)
    active = [f for f in findings if not f.false_positive]

    env = _build_env()

    tpl_file = f"{template_name}.html"
    available = [str(p.relative_to(settings.TEMPLATES_DIR)).replace("\\", "/")[:-5] for p in settings.TEMPLATES_DIR.glob("**/*.html")]

    if template_name not in available:
        log.warning("Template '%s' not found, falling back to default_report", template_name)
        tpl_file = "default_report.html"

    try:
        tpl = env.get_template(tpl_file)
    except Exception as e:
        log.error("Template load error: %s", e)
        # Fallback: inline minimal template
        return _inline_render(meta, active, stats)

    # VA template variables
    total_pages = len(active) + 10  # approximate: cover + toc + fixed sections + one page per finding
    checklist_status: dict = {}     # template uses its own default ("Validated") when key absent

    return tpl.render(
        report=meta,
        findings=active,
        finding_stats=stats,
        all_findings=findings,
        total_pages=total_pages,
        checklist_status=checklist_status,
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
    )


def _inline_render(meta: ReportMeta, findings: List[Finding], stats: FindingStats) -> str:
    """Minimal inline fallback template (no file dependency)."""
    esc = html_mod.escape
    rows = "".join(
        f'<tr><td>{esc(f.title)}</td>'
        f'<td style="background:{SEV_COLORS.get(f.cvss.level,("#6e6e6e","#fff"))[0]};'
        f'color:{SEV_COLORS.get(f.cvss.level,("#6e6e6e","#fff"))[1]};text-align:center;font-weight:700">'
        f'{f.cvss.level.capitalize()}</td></tr>'
        for f in findings
    )
    return f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>VAPT Report — {esc(meta.client_name or "Client")}</title>
<style>body{{font-family:Garamond,serif;padding:40px;max-width:900px;margin:0 auto}}
table{{width:100%;border-collapse:collapse}}th,td{{border:1px solid #1f86d0;padding:8px}}
th{{background:#1f86d0;color:#fff}}</style></head><body>
<h1>VAPT Report — {esc(meta.client_name or "")}</h1>
<h2>Findings Summary</h2>
<table><tr><th>Vulnerability</th><th>Severity</th></tr>{rows}</table>
<p>Critical: {stats.count_critical} | High: {stats.count_high} | Medium: {stats.count_medium} |
Low: {stats.count_low} | Info: {stats.count_info}</p>
</body></html>"""
