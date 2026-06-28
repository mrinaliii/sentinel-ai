"""
Incident Report Generation Service
=====================================
Produces professional SOC incident reports in Markdown and PDF formats
from alert analysis, MITRE ATT&CK mappings, and analyst investigation notes.

Architecture
------------
::

    ReportRequest                      ← validated input (alert analysis + MITRE + notes)
           │
           ▼
    IncidentReportGenerator
           │
           ├─ generate_markdown()      Renders a structured Markdown report
           │
           ├─ export_pdf()             Converts Markdown → styled HTML (Jinja2 template)
           │                           → PDF (WeasyPrint)
           │
           └─ generate_report()        Orchestrates both, persists files, returns ReportResult

Design principles
-----------------
* **No external API calls** — purely local: Jinja2 + markdown + weasyprint.
* **Graceful degradation** — PDF export degrades gracefully if weasyprint is
  not installed; the service still returns the Markdown content.
* **Testable without weasyprint** — pass ``pdf_enabled=False`` to skip PDF.
* **Idempotent** — report_id is part of the filename; re-generating the same
  report_id simply overwrites the output files.
* **Storage-agnostic** — output directory is configurable; defaults to
  ``{package_root}/reports/``.  Plug in S3, GCS, etc. by subclassing.
"""

from __future__ import annotations

import json
import logging
import textwrap
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Optional imports — degrade gracefully
try:
    import markdown as _markdown_lib  # type: ignore[import]

    _MARKDOWN_AVAILABLE = True
except ImportError:
    _markdown_lib = None  # type: ignore[assignment]
    _MARKDOWN_AVAILABLE = False

try:
    import jinja2  # type: ignore[import]

    _JINJA2_AVAILABLE = True
except ImportError:
    jinja2 = None  # type: ignore[assignment]
    _JINJA2_AVAILABLE = False

try:
    from weasyprint import HTML as _WeasyprintHTML  # type: ignore[import]

    _WEASYPRINT_AVAILABLE = True
except ImportError:
    _WeasyprintHTML = None  # type: ignore[assignment]
    _WEASYPRINT_AVAILABLE = False


# ---------------------------------------------------------------------------
# Local models (imported lazily to avoid circular deps at module level)
# ---------------------------------------------------------------------------

from app.models.report import (
    AlertAnalysisInput,
    IOCSummary,
    MitreMatchInput,
    ReportFormat,
    ReportMetadata,
    ReportRequest,
    ReportResult,
    ReportSeverity,
    TimelineEvent,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_REPORTS_DIR = Path(__file__).parent.parent / "reports"
_TEMPLATE_DIR = Path(__file__).parent.parent / "templates"
_TEMPLATE_NAME = "incident_report.html"

_SEVERITY_EMOJI: Dict[str, str] = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
    "informational": "🔵",
}

_CONFIDENCE_LABEL: Dict[str, str] = {
    "high": "HIGH",
    "med": "MEDIUM",
    "low": "LOW",
}


# ---------------------------------------------------------------------------
# Markdown renderer helpers
# ---------------------------------------------------------------------------


def _confidence_bar(value: float, width: int = 20) -> str:
    """Return an ASCII progress bar for inline Markdown."""
    filled = round(value * width)
    return f"[{'█' * filled}{'░' * (width - filled)}] {int(value * 100):>3}%"


def _severity_badge(severity: str) -> str:
    emoji = _SEVERITY_EMOJI.get(severity.lower(), "⚪")
    return f"{emoji} **{severity.upper()}**"


def _format_dt(dt: Optional[datetime], fmt: str = "%Y-%m-%d %H:%M:%S UTC") -> str:
    if dt is None:
        return "N/A"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.strftime(fmt)


def _md_table(headers: List[str], rows: List[List[str]]) -> str:
    """Render a GitHub-flavoured Markdown table."""
    sep = ["-" * max(len(h), 3) for h in headers]
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(sep) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(str(c) for c in row) + " |")
    return "\n".join(lines)


def _wrap(text: str, indent: int = 0) -> str:
    """Lightly wrap long lines in narrative blocks."""
    return textwrap.fill(text, width=100, initial_indent=" " * indent, subsequent_indent=" " * indent)


# ---------------------------------------------------------------------------
# Core service
# ---------------------------------------------------------------------------


class IncidentReportGenerator:
    """
    Generates professional SOC incident reports from structured inputs.

    Parameters
    ----------
    reports_dir : Path, optional
        Directory where ``.md`` and ``.pdf`` files are saved.
        Defaults to ``{package_root}/reports/``.
    pdf_enabled : bool
        If False, PDF export is skipped even if weasyprint is installed.
        Useful for tests.
    template_dir : Path, optional
        Directory containing Jinja2 templates.
    """

    def __init__(
        self,
        reports_dir: Optional[Path] = None,
        pdf_enabled: bool = True,
        template_dir: Optional[Path] = None,
    ) -> None:
        self.reports_dir = Path(reports_dir or _DEFAULT_REPORTS_DIR)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

        self.pdf_enabled = pdf_enabled and _WEASYPRINT_AVAILABLE
        self._template_dir = Path(template_dir or _TEMPLATE_DIR)

        # Jinja2 environment (lazy — only built on first PDF call)
        self._jinja_env: Optional[Any] = None

    # ── Public API ──────────────────────────────────────────────────────────

    def generate_markdown(self, request: ReportRequest) -> str:
        """
        Render a complete SOC incident report in GitHub-flavoured Markdown.

        Parameters
        ----------
        request : ReportRequest
            Fully populated report request.

        Returns
        -------
        str
            The complete Markdown document as a string.
        """
        report_id = str(uuid.uuid4())
        generated_at = datetime.utcnow()

        sections: List[str] = []

        # ── Title block ────────────────────────────────────────────────
        sections.append(self._md_title_block(request, report_id, generated_at))

        # ── 1. Executive Summary ───────────────────────────────────────
        sections.append(self._md_executive_summary(request))

        # ── 2. Risk Assessment ─────────────────────────────────────────
        sections.append(self._md_risk_assessment(request))

        # ── 3. MITRE ATT&CK Mapping ────────────────────────────────────
        if request.mitre_matches:
            sections.append(self._md_mitre_section(request.mitre_matches))

        # ── 4. Investigation Notes ─────────────────────────────────────
        if request.investigation_notes.strip():
            sections.append(self._md_investigation_notes(request.investigation_notes))

        # ── 5. Investigation Steps ─────────────────────────────────────
        if request.alert_analysis.investigation_steps:
            sections.append(
                self._md_numbered_list(
                    "🔬 5. Recommended Investigation Steps",
                    request.alert_analysis.investigation_steps,
                )
            )

        # ── 6. Recommended Actions ─────────────────────────────────────
        if request.alert_analysis.recommended_actions:
            sections.append(
                self._md_numbered_list(
                    "🛡️ 6. Recommended Remediation Actions",
                    request.alert_analysis.recommended_actions,
                )
            )

        # ── 7. IOC Table ───────────────────────────────────────────────
        if request.iocs:
            sections.append(self._md_ioc_section(request.iocs))

        # ── 8. Forensic Timeline ───────────────────────────────────────
        if request.timeline:
            sections.append(self._md_timeline_section(request.timeline))

        # ── 9. Appendix ────────────────────────────────────────────────
        if request.include_appendix and request.raw_alert_metadata:
            sections.append(self._md_appendix(request.raw_alert_metadata))

        # ── Footer ─────────────────────────────────────────────────────
        sections.append(self._md_footer(request, report_id, generated_at))

        return "\n\n---\n\n".join(sections)

    def export_pdf(
        self,
        request: ReportRequest,
        markdown_content: str,
        report_id: str,
        generated_at: Optional[datetime] = None,
    ) -> bytes:
        """
        Convert a report request + its pre-rendered Markdown to a PDF byte string.

        Uses a Jinja2 HTML template rendered to PDF via WeasyPrint.

        Parameters
        ----------
        request : ReportRequest
        markdown_content : str
            Already-rendered Markdown (used to derive word count; the HTML
            template is rendered independently from the request for rich styling).
        report_id : str
        generated_at : datetime, optional

        Returns
        -------
        bytes
            Raw PDF binary content.

        Raises
        ------
        RuntimeError
            If WeasyPrint is not installed.
        """
        if not _WEASYPRINT_AVAILABLE:
            raise RuntimeError(
                "WeasyPrint is not installed. Install it with: pip install weasyprint"
            )
        if not _JINJA2_AVAILABLE:
            raise RuntimeError(
                "Jinja2 is not installed. Install it with: pip install jinja2"
            )

        html_content = self._render_html_template(request, report_id, generated_at)

        logger.info("report_pdf_rendering: report_id=%s", report_id)
        pdf_bytes: bytes = _WeasyprintHTML(  # type: ignore[misc]
            string=html_content, base_url=str(self._template_dir)
        ).write_pdf()
        logger.info(
            "report_pdf_rendered: report_id=%s size_bytes=%d", report_id, len(pdf_bytes)
        )
        return pdf_bytes

    def generate_report(self, request: ReportRequest) -> ReportResult:
        """
        Orchestrate the full report generation pipeline.

        1. Generates Markdown content.
        2. Saves ``.md`` file to ``reports_dir``.
        3. If ``format`` includes PDF and WeasyPrint is available, renders and saves ``.pdf``.
        4. Returns a ``ReportResult`` with all metadata.

        Parameters
        ----------
        request : ReportRequest

        Returns
        -------
        ReportResult
        """
        report_id = str(uuid.uuid4())
        generated_at = datetime.utcnow()

        logger.info(
            "report_generation_started: report_id=%s incident_id=%s format=%s",
            report_id, request.incident_id, request.format,
        )

        # ── Step 1: Markdown ───────────────────────────────────────────
        md_content = self._generate_markdown_with_id(request, report_id, generated_at)

        # ── Step 2: Persist Markdown ───────────────────────────────────
        md_path: Optional[Path] = None
        if request.format in (ReportFormat.MARKDOWN, ReportFormat.BOTH):
            md_path = self.reports_dir / f"{report_id}.md"
            md_path.write_text(md_content, encoding="utf-8")
            logger.info("report_md_saved: path=%s", md_path)

        # ── Step 3: PDF ────────────────────────────────────────────────
        pdf_path: Optional[Path] = None
        has_pdf = False

        if request.format in (ReportFormat.PDF, ReportFormat.BOTH):
            if self.pdf_enabled:
                try:
                    pdf_bytes = self.export_pdf(request, md_content, report_id, generated_at)
                    pdf_path = self.reports_dir / f"{report_id}.pdf"
                    pdf_path.write_bytes(pdf_bytes)
                    has_pdf = True
                    logger.info("report_pdf_saved: path=%s", pdf_path)
                except Exception as exc:
                    logger.error(
                        "report_pdf_failed: report_id=%s error=%s",
                        report_id, str(exc)[:200],
                    )
            else:
                logger.warning(
                    "report_pdf_skipped: report_id=%s reason=pdf_disabled_or_weasyprint_unavailable",
                    report_id,
                )

        word_count = len(md_content.split())
        result = ReportResult(
            report_id=report_id,
            incident_id=request.incident_id,
            title=request.title,
            severity=request.severity,
            generated_at=generated_at,
            generated_by=request.analyst_name,
            markdown_content=md_content,
            pdf_path=str(pdf_path) if pdf_path else None,
            markdown_path=str(md_path) if md_path else None,
            word_count=word_count,
            mitre_technique_count=len(request.mitre_matches),
            ioc_count=len(request.iocs),
            has_pdf=has_pdf,
        )

        logger.info(
            "report_generation_complete: report_id=%s words=%d has_pdf=%s",
            report_id, word_count, has_pdf,
        )
        return result

    def get_report_metadata(self, report_id: str) -> Optional[ReportMetadata]:
        """
        Reconstruct minimal metadata from on-disk files for a given report_id.

        Returns None if no files exist for that ID.
        """
        md_path = self.reports_dir / f"{report_id}.md"
        pdf_path = self.reports_dir / f"{report_id}.pdf"

        if not md_path.exists():
            return None

        # Parse the first few lines of the saved Markdown to recover metadata
        content = md_path.read_text(encoding="utf-8")
        title = self._extract_md_field(content, "title") or "Unknown"
        severity_str = self._extract_md_field(content, "severity") or "medium"
        analyst = self._extract_md_field(content, "analyst") or "Unknown"
        incident_id = self._extract_md_field(content, "incident_id") or report_id

        try:
            severity = ReportSeverity(severity_str.lower())
        except ValueError:
            severity = ReportSeverity.MEDIUM

        word_count = len(content.split())
        mitre_count = content.count("| T")  # rough heuristic from table rows

        return ReportMetadata(
            report_id=report_id,
            incident_id=incident_id,
            title=title,
            severity=severity,
            generated_at=datetime.fromtimestamp(md_path.stat().st_mtime),
            generated_by=analyst,
            has_pdf=pdf_path.exists(),
            pdf_path=str(pdf_path) if pdf_path.exists() else None,
            markdown_path=str(md_path),
            word_count=word_count,
            mitre_technique_count=max(mitre_count - 1, 0),  # subtract header row
        )

    def get_markdown(self, report_id: str) -> Optional[str]:
        """Return saved Markdown content for a report_id, or None if not found."""
        md_path = self.reports_dir / f"{report_id}.md"
        if not md_path.exists():
            return None
        return md_path.read_text(encoding="utf-8")

    def get_pdf_bytes(self, report_id: str) -> Optional[bytes]:
        """Return saved PDF bytes for a report_id, or None if not found."""
        pdf_path = self.reports_dir / f"{report_id}.pdf"
        if not pdf_path.exists():
            return None
        return pdf_path.read_bytes()

    # ── Markdown rendering helpers ───────────────────────────────────────────

    def _generate_markdown_with_id(
        self,
        request: ReportRequest,
        report_id: str,
        generated_at: datetime,
    ) -> str:
        """Internal variant that takes a pre-determined report_id."""
        sections: List[str] = []
        sections.append(self._md_title_block(request, report_id, generated_at))
        sections.append(self._md_executive_summary(request))
        sections.append(self._md_risk_assessment(request))

        if request.mitre_matches:
            sections.append(self._md_mitre_section(request.mitre_matches))

        if request.investigation_notes.strip():
            sections.append(self._md_investigation_notes(request.investigation_notes))

        if request.alert_analysis.investigation_steps:
            sections.append(
                self._md_numbered_list(
                    "🔬 5. Recommended Investigation Steps",
                    request.alert_analysis.investigation_steps,
                )
            )

        if request.alert_analysis.recommended_actions:
            sections.append(
                self._md_numbered_list(
                    "🛡️ 6. Recommended Remediation Actions",
                    request.alert_analysis.recommended_actions,
                )
            )

        if request.iocs:
            sections.append(self._md_ioc_section(request.iocs))

        if request.timeline:
            sections.append(self._md_timeline_section(request.timeline))

        if request.include_appendix and request.raw_alert_metadata:
            sections.append(self._md_appendix(request.raw_alert_metadata))

        sections.append(self._md_footer(request, report_id, generated_at))
        return "\n\n---\n\n".join(sections)

    def _md_title_block(
        self,
        request: ReportRequest,
        report_id: str,
        generated_at: datetime,
    ) -> str:
        sev_badge = _severity_badge(request.severity.value)
        tags_str = " · ".join(f"`{t}`" for t in request.tags) if request.tags else "—"

        meta_rows = [
            ("Report ID", f"`{report_id}`"),
            ("Incident ID", f"`{request.incident_id}`"),
            ("Severity", sev_badge),
            ("Status", f"**{request.status}**"),
            ("Classification", request.classification or "—"),
            ("Analyst", request.analyst_name),
            ("Organization", request.organization),
            ("Detected At", _format_dt(request.detected_at)),
            ("Reported At", _format_dt(request.reported_at)),
            ("Generated At", _format_dt(generated_at)),
            ("Tags", tags_str),
        ]

        table = _md_table(["Field", "Value"], [[k, v] for k, v in meta_rows])

        hosts = (
            " · ".join(f"`{h}`" for h in request.affected_hosts)
            if request.affected_hosts
            else "—"
        )
        users = (
            " · ".join(f"`{u}`" for u in request.affected_users)
            if request.affected_users
            else "—"
        )

        return f"""# 🛡️ SOC Incident Report

## {request.title}

> **⚠ CONFIDENTIAL — INTERNAL SOC USE ONLY**

{table}

**Affected Hosts:** {hosts}
**Affected Users:** {users}
**Source System:** {request.source_system or "—"}"""

    def _md_executive_summary(self, request: ReportRequest) -> str:
        return f"""## 🔎 1. Executive Summary

{_wrap(request.alert_analysis.summary)}"""

    def _md_risk_assessment(self, request: ReportRequest) -> str:
        return f"""## ⚡ 2. Risk Assessment & Business Impact

> {request.alert_analysis.risk_assessment}"""

    def _md_mitre_section(self, matches: List[MitreMatchInput]) -> str:
        headers = [
            "Technique ID",
            "Name",
            "Tactic",
            "Confidence",
            "Method",
            "Rationale",
        ]
        rows = []
        for m in matches:
            tid = m.technique_id
            if m.sub_technique_id:
                tid = f"{m.technique_id} / {m.sub_technique_id}"
            name = m.technique_name
            if m.sub_technique:
                name = f"{m.technique_name} ↳ {m.sub_technique}"
            conf_bar = _confidence_bar(m.confidence, width=10)
            rows.append(
                [
                    f"`{tid}`",
                    name,
                    f"{m.tactic} (`{m.tactic_id}`)",
                    conf_bar,
                    f"`{m.mapping_method}`",
                    m.rationale or "—",
                ]
            )

        table = _md_table(headers, rows)
        return f"""## 🎯 3. MITRE ATT&CK Technique Mapping

{table}"""

    def _md_investigation_notes(self, notes: str) -> str:
        return f"""## 📋 4. Investigation Notes

{notes.strip()}"""

    def _md_numbered_list(self, heading: str, items: List[str]) -> str:
        lines = [f"{i + 1}. {item}" for i, item in enumerate(items)]
        return f"""## {heading}

{chr(10).join(lines)}"""

    def _md_ioc_section(self, iocs: List[IOCSummary]) -> str:
        headers = ["Indicator", "Type", "Verdict", "Rep. Score", "Sources", "Tags"]
        rows = []
        for ioc in iocs:
            if ioc.malicious is True:
                verdict = "⛔ MALICIOUS"
            elif ioc.malicious is False:
                verdict = "✓ Clean"
            else:
                verdict = "— Unknown"

            score = f"{ioc.reputation_score:.1f}" if ioc.reputation_score is not None else "—"
            sources = ", ".join(ioc.sources) if ioc.sources else "—"
            tags = ", ".join(ioc.tags) if ioc.tags else "—"

            rows.append(
                [f"`{ioc.value}`", f"`{ioc.ioc_type}`", verdict, score, sources, tags]
            )

        return f"""## 🔴 7. Indicators of Compromise (IOCs)

{_md_table(headers, rows)}"""

    def _md_timeline_section(self, events: List[TimelineEvent]) -> str:
        lines = ["## ⏱️ 8. Forensic Event Timeline", ""]
        for event in sorted(events, key=lambda e: e.timestamp):
            ts = _format_dt(event.timestamp, "%Y-%m-%d %H:%M:%S UTC")
            actor = f" · by `{event.actor}`" if event.actor else ""
            ref = f" · ref:`{event.reference_id}`" if event.reference_id else ""
            lines.append(
                f"- **`{ts}`** `[{event.event_type.upper()}]`{actor}{ref}  \n"
                f"  {event.description}"
            )
        return "\n".join(lines)

    def _md_appendix(self, metadata: Dict[str, Any]) -> str:
        json_str = json.dumps(metadata, indent=2, default=str)
        return f"""## 📎 Appendix — Raw Alert Metadata

> Raw alert data as ingested. For forensic reference only.

```json
{json_str}
```"""

    def _md_footer(
        self,
        request: ReportRequest,
        report_id: str,
        generated_at: datetime,
    ) -> str:
        return f"""---

*Report generated by **Sentinel-AI v1** · {_format_dt(generated_at)}*  
*Analyst: **{request.analyst_name}**{f' <{request.analyst_email}>' if request.analyst_email else ''} · {request.organization}*  
*Report ID: `{report_id}` · Incident: `{request.incident_id}`*

> **CONFIDENTIAL** — This document is intended solely for the recipient(s) named above.
> Unauthorized disclosure, copying, or distribution is strictly prohibited."""

    # ── HTML / PDF rendering helpers ─────────────────────────────────────────

    def _get_jinja_env(self) -> Any:
        """Return (and lazily build) the Jinja2 environment."""
        if self._jinja_env is not None:
            return self._jinja_env

        if not _JINJA2_AVAILABLE:
            raise RuntimeError("Jinja2 is not installed.")

        self._jinja_env = jinja2.Environment(  # type: ignore[attr-defined]
            loader=jinja2.FileSystemLoader(str(self._template_dir)),
            autoescape=jinja2.select_autoescape(["html"]),
        )
        return self._jinja_env

    def _render_html_template(
        self,
        request: ReportRequest,
        report_id: str,
        generated_at: Optional[datetime],
    ) -> str:
        """Render the Jinja2 HTML template for PDF conversion."""
        env = self._get_jinja_env()
        template = env.get_template(_TEMPLATE_NAME)

        # Convert investigation_notes markdown → HTML if markdown lib available
        notes_html = ""
        if request.investigation_notes.strip():
            if _MARKDOWN_AVAILABLE:
                notes_html = _markdown_lib.markdown(
                    request.investigation_notes,
                    extensions=["tables", "fenced_code", "nl2br"],
                )
            else:
                notes_html = f"<p>{request.investigation_notes}</p>"

        # Format timestamps for display
        detected = _format_dt(request.detected_at)
        reported = _format_dt(request.reported_at)
        gen_at = _format_dt(generated_at or datetime.utcnow())

        # Serialize raw metadata for appendix
        raw_json = ""
        if request.raw_alert_metadata:
            raw_json = json.dumps(request.raw_alert_metadata, indent=2, default=str)

        # Sort timeline chronologically
        timeline_sorted = sorted(request.timeline, key=lambda e: e.timestamp)

        ctx: Dict[str, Any] = {
            # Metadata
            "report_id": report_id,
            "incident_id": request.incident_id,
            "title": request.title,
            "severity": request.severity.value,
            "status": request.status,
            "classification": request.classification,
            "organization": request.organization,
            "analyst_name": request.analyst_name,
            "analyst_email": request.analyst_email,
            "detected_at": detected,
            "reported_at": reported,
            "generated_at": gen_at,
            "tags": request.tags,
            # Asset context
            "affected_hosts": request.affected_hosts,
            "affected_users": request.affected_users,
            "source_system": request.source_system,
            # Intelligence
            "alert_analysis": request.alert_analysis,
            "mitre_matches": request.mitre_matches,
            # Analyst inputs
            "investigation_notes": request.investigation_notes,
            "investigation_notes_html": notes_html,
            "iocs": request.iocs,
            "timeline": timeline_sorted,
            # Appendix
            "include_appendix": request.include_appendix,
            "raw_alert_metadata": request.raw_alert_metadata,
            "raw_alert_json": raw_json,
        }

        return template.render(**ctx)

    # ── Metadata parsing helpers ──────────────────────────────────────────────

    @staticmethod
    def _extract_md_field(content: str, field: str) -> Optional[str]:
        """
        Extract a value from lines like ``| Field | Value |`` in the title table.
        Used to reconstruct metadata from saved Markdown.
        """
        field_lower = field.lower()
        for line in content.splitlines():
            if "|" not in line:
                continue
            parts = [p.strip() for p in line.strip("|").split("|")]
            if len(parts) >= 2:
                key = parts[0].lower().replace(" ", "_")
                if key == field_lower:
                    # Strip Markdown formatting artifacts
                    val = parts[1].strip().strip("`").strip("*")
                    # Strip emoji
                    for emoji in _SEVERITY_EMOJI.values():
                        val = val.replace(emoji, "").strip()
                    return val or None
        return None


# ---------------------------------------------------------------------------
# Factory / singleton helper
# ---------------------------------------------------------------------------

_default_generator: Optional[IncidentReportGenerator] = None


def get_generator(
    reports_dir: Optional[Path] = None,
    pdf_enabled: bool = True,
) -> IncidentReportGenerator:
    """
    Return (and lazily initialise) a module-level singleton generator.

    Usage::

        from app.services.report_generator import get_generator
        gen = get_generator()
        result = gen.generate_report(request)
    """
    global _default_generator
    if _default_generator is None:
        _default_generator = IncidentReportGenerator(
            reports_dir=reports_dir, pdf_enabled=pdf_enabled
        )
    return _default_generator
