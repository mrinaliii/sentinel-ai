"""
Unit Tests – LangChain Alert Analysis Service
===============================================
All LLM calls are mocked — no Ollama instance required.

Test coverage:
- AlertAnalysisRequest schema & from_dicts()
- AlertAnalysis schema validation
- _build_human_prompt() rendering
- _heuristic_analysis() for each severity
- AlertAnalyzer.analyze() – dry_run mode
- AlertAnalyzer.analyze() – LLM success path (mocked)
- AlertAnalyzer.analyze() – JSON parse failure → fallback
- AlertAnalyzer.analyze() – validation failure → fallback
- AlertAnalyzer.analyze() – transient LLM error with retry
- AlertAnalyzer.analyze() – all retries exhausted → fallback
- AlertAnalyzer._parse_llm_output() edge cases
- create_analyzer() factory

Run with::

    pytest tests/test_llm_analyzer.py -v
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import ValidationError

from app.services.llm_analyzer import (
    AlertAnalysis,
    AlertAnalysisRequest,
    AlertAnalyzer,
    MitreMatchInput,
    _build_human_prompt,
    _heuristic_analysis,
    create_analyzer,
)


# ===========================================================================
# Fixtures
# ===========================================================================


@pytest.fixture()
def mitre_matches() -> List[Dict[str, Any]]:
    return [
        {
            "technique_id": "T1059.001",
            "technique_name": "PowerShell",
            "tactic": "Execution",
            "tactic_id": "TA0002",
            "confidence": 0.92,
            "mapping_method": "exact_id",
            "rationale": "Explicit technique ID T1059.001 found in alert text",
        },
        {
            "technique_id": "T1003",
            "technique_name": "OS Credential Dumping",
            "tactic": "Credential Access",
            "tactic_id": "TA0006",
            "confidence": 0.75,
            "mapping_method": "keyword",
            "rationale": "Matched tokens: lsass, memory, dump",
        },
    ]


@pytest.fixture()
def alert_dict() -> Dict[str, Any]:
    return {
        "timestamp": "2024-06-01T12:34:56+00:00",
        "source": "wazuh",
        "severity": "high",
        "alert_name": "Shellshock Attack Detected",
        "host": "web-server-01",
        "user": "apache",
        "raw_log": json.dumps(
            {"rule": {"description": "Shellshock attack", "level": 14},
             "agent": {"name": "web-server-01"}}
        ),
    }


@pytest.fixture()
def analysis_request(alert_dict, mitre_matches) -> AlertAnalysisRequest:
    return AlertAnalysisRequest.from_dicts(
        alert=alert_dict,
        mitre_matches=mitre_matches,
    )


@pytest.fixture()
def valid_llm_json() -> str:
    return json.dumps({
        "summary": "A high-severity Shellshock attack was detected on web-server-01.",
        "risk_assessment": "Rated HIGH due to active exploitation of CVE-2014-6271.",
        "investigation_steps": [
            "Review Apache access logs on web-server-01.",
            "Check for unexpected child processes spawned by bash.",
            "Search for lateral movement from web-server-01.",
        ],
        "recommended_actions": [
            "Isolate web-server-01 from the network.",
            "Patch bash to the latest version.",
            "Reset apache service account credentials.",
        ],
    })


@pytest.fixture()
def dry_run_analyzer() -> AlertAnalyzer:
    return AlertAnalyzer(dry_run=True)


# ===========================================================================
# MitreMatchInput
# ===========================================================================


class TestMitreMatchInput:
    def test_valid_input(self, mitre_matches):
        m = MitreMatchInput(**mitre_matches[0])
        assert m.technique_id == "T1059.001"
        assert m.confidence == 0.92

    def test_rationale_optional(self, mitre_matches):
        data = {**mitre_matches[0], "rationale": None}
        m = MitreMatchInput(**data)
        assert m.rationale is None

    def test_missing_required_field_raises(self, mitre_matches):
        data = {k: v for k, v in mitre_matches[0].items() if k != "technique_id"}
        with pytest.raises(ValidationError):
            MitreMatchInput(**data)


# ===========================================================================
# AlertAnalysisRequest
# ===========================================================================


class TestAlertAnalysisRequest:
    def test_from_dicts_populates_fields(self, alert_dict, mitre_matches):
        req = AlertAnalysisRequest.from_dicts(alert=alert_dict, mitre_matches=mitre_matches)
        assert req.alert_name == "Shellshock Attack Detected"
        assert req.host == "web-server-01"
        assert req.severity == "high"
        assert len(req.mitre_matches) == 2

    def test_from_dicts_no_mitre(self, alert_dict):
        req = AlertAnalysisRequest.from_dicts(alert=alert_dict)
        assert req.mitre_matches == []

    def test_from_dicts_analyst_hint(self, alert_dict):
        req = AlertAnalysisRequest.from_dicts(
            alert=alert_dict, analyst_hint="Focus on process injection"
        )
        assert req.analyst_hint == "Focus on process injection"

    def test_defaults_for_missing_optional_fields(self):
        req = AlertAnalysisRequest.from_dicts(alert={
            "timestamp": "2024-01-01T00:00:00Z",
            "source": "splunk",
            "severity": "low",
            "alert_name": "Test",
        })
        assert req.host == "unknown"
        assert req.user == "unknown"
        assert req.raw_log == "{}"

    def test_direct_construction(self):
        req = AlertAnalysisRequest(
            timestamp="2024-01-01T00:00:00Z",
            source="splunk",
            severity="critical",
            alert_name="Ransomware",
        )
        assert req.severity == "critical"


# ===========================================================================
# AlertAnalysis (output schema)
# ===========================================================================


class TestAlertAnalysis:
    def _make(self, **overrides) -> Dict[str, Any]:
        base = {
            "summary": "Test summary.",
            "risk_assessment": "Risk is high.",
            "investigation_steps": ["Step one", "Step two"],
            "recommended_actions": ["Action one"],
        }
        base.update(overrides)
        return base

    def test_valid_analysis(self):
        a = AlertAnalysis(**self._make())
        assert a.summary == "Test summary."
        assert len(a.investigation_steps) == 2

    def test_to_dict_has_all_keys(self):
        a = AlertAnalysis(**self._make())
        d = a.to_dict()
        assert set(d.keys()) == {
            "summary", "risk_assessment",
            "investigation_steps", "recommended_actions"
        }

    def test_empty_steps_raises(self):
        with pytest.raises(ValidationError):
            AlertAnalysis(**self._make(investigation_steps=[]))

    def test_empty_actions_raises(self):
        with pytest.raises(ValidationError):
            AlertAnalysis(**self._make(recommended_actions=[]))

    def test_missing_summary_raises(self):
        data = self._make()
        del data["summary"]
        with pytest.raises(ValidationError):
            AlertAnalysis(**data)


# ===========================================================================
# _build_human_prompt
# ===========================================================================


class TestBuildHumanPrompt:
    def test_contains_alert_name(self, analysis_request):
        prompt = _build_human_prompt(analysis_request)
        assert "Shellshock Attack Detected" in prompt

    def test_contains_host_and_user(self, analysis_request):
        prompt = _build_human_prompt(analysis_request)
        assert "web-server-01" in prompt
        assert "apache" in prompt

    def test_contains_severity(self, analysis_request):
        prompt = _build_human_prompt(analysis_request)
        assert "HIGH" in prompt

    def test_contains_mitre_technique_ids(self, analysis_request):
        prompt = _build_human_prompt(analysis_request)
        assert "T1059.001" in prompt
        assert "T1003" in prompt

    def test_mitre_section_absent_when_empty(self, alert_dict):
        req = AlertAnalysisRequest.from_dicts(alert=alert_dict)
        prompt = _build_human_prompt(req)
        assert "MITRE ATT&CK Mappings" not in prompt

    def test_analyst_hint_included(self, alert_dict):
        req = AlertAnalysisRequest.from_dicts(
            alert=alert_dict, analyst_hint="Focus on lateral movement"
        )
        prompt = _build_human_prompt(req)
        assert "Focus on lateral movement" in prompt

    def test_raw_log_truncated(self):
        big_log = json.dumps({"data": "A" * 5000})
        req = AlertAnalysisRequest.from_dicts(alert={
            "timestamp": "2024-01-01T00:00:00Z",
            "source": "splunk",
            "severity": "low",
            "alert_name": "Big Log Alert",
            "raw_log": big_log,
        })
        prompt = _build_human_prompt(req)
        # Raw log section should be capped
        raw_section = prompt.split("Raw Log (truncated):\n")[1]
        assert len(raw_section) < 5000

    def test_prompt_contains_json_instruction(self, analysis_request):
        prompt = _build_human_prompt(analysis_request)
        assert "JSON" in prompt or "json" in prompt

    def test_mitre_capped_at_five(self, alert_dict):
        many_matches = [
            {
                "technique_id": f"T100{i}",
                "technique_name": f"Technique {i}",
                "tactic": "Execution",
                "tactic_id": "TA0002",
                "confidence": 0.5,
                "mapping_method": "keyword",
            }
            for i in range(10)
        ]
        req = AlertAnalysisRequest.from_dicts(alert=alert_dict, mitre_matches=many_matches)
        prompt = _build_human_prompt(req)
        # Only first 5 appear
        for i in range(5):
            assert f"T100{i}" in prompt
        assert "T1005" not in prompt  # index 5+ should not appear


# ===========================================================================
# _heuristic_analysis
# ===========================================================================


class TestHeuristicAnalysis:
    @pytest.mark.parametrize("severity", ["critical", "high", "medium", "low", "informational"])
    def test_all_severities_produce_valid_analysis(self, alert_dict, severity):
        req = AlertAnalysisRequest.from_dicts(alert={**alert_dict, "severity": severity})
        result = _heuristic_analysis(req)
        assert isinstance(result, AlertAnalysis)
        assert result.summary
        assert result.risk_assessment
        assert len(result.investigation_steps) > 0
        assert len(result.recommended_actions) > 0

    def test_critical_contains_isolation_step(self, alert_dict):
        req = AlertAnalysisRequest.from_dicts(alert={**alert_dict, "severity": "critical"})
        result = _heuristic_analysis(req)
        combined = " ".join(result.recommended_actions).lower()
        assert "isolate" in combined

    def test_host_in_summary(self, alert_dict):
        req = AlertAnalysisRequest.from_dicts(alert=alert_dict)
        result = _heuristic_analysis(req)
        assert "web-server-01" in result.summary

    def test_mitre_refs_in_summary_when_present(self, analysis_request):
        result = _heuristic_analysis(analysis_request)
        assert "T1059.001" in result.summary or "T1003" in result.summary

    def test_no_mitre_refs_when_empty(self, alert_dict):
        req = AlertAnalysisRequest.from_dicts(alert=alert_dict)
        result = _heuristic_analysis(req)
        assert "no MITRE mapping available" in result.summary

    def test_unknown_severity_falls_back_to_medium(self, alert_dict):
        req = AlertAnalysisRequest.from_dicts(alert={**alert_dict, "severity": "unknown"})
        result = _heuristic_analysis(req)
        # Should not raise; risk_assessment falls back to medium text
        assert result.risk_assessment


# ===========================================================================
# AlertAnalyzer – dry_run mode
# ===========================================================================


class TestAlertAnalyzerDryRun:
    @pytest.mark.asyncio
    async def test_dry_run_returns_heuristic(self, dry_run_analyzer, analysis_request):
        result = await dry_run_analyzer.analyze(analysis_request)
        assert isinstance(result, AlertAnalysis)
        assert result.summary  # non-empty

    @pytest.mark.asyncio
    async def test_dry_run_does_not_call_llm(self, analysis_request):
        analyzer = AlertAnalyzer(dry_run=True)
        with patch.object(analyzer, "_ensure_chain") as mock:
            await analyzer.analyze(analysis_request)
            mock.assert_not_called()

    @pytest.mark.asyncio
    async def test_dry_run_high_severity_has_isolation_action(self, dry_run_analyzer, alert_dict):
        req = AlertAnalysisRequest.from_dicts(alert={**alert_dict, "severity": "high"})
        result = await dry_run_analyzer.analyze(req)
        combined = " ".join(result.recommended_actions).lower()
        assert "isolate" in combined


# ===========================================================================
# AlertAnalyzer – LLM success path (mocked)
# ===========================================================================


class TestAlertAnalyzerLLMSuccess:
    def _make_analyzer_with_mock_chain(self, response_json: str) -> AlertAnalyzer:
        """Return an AlertAnalyzer whose chain returns response_json."""
        analyzer = AlertAnalyzer(dry_run=False)
        mock_chain = AsyncMock()
        mock_chain.ainvoke = AsyncMock(return_value=response_json)
        analyzer._chain = mock_chain
        analyzer._system_msg = MagicMock()
        return analyzer

    def _patch_langchain(self):
        """Context manager that makes _LANGCHAIN_AVAILABLE=True and stubs HumanMessage."""
        import app.services.llm_analyzer as mod
        return patch.multiple(
            mod,
            _LANGCHAIN_AVAILABLE=True,
            HumanMessage=MagicMock(side_effect=lambda content: MagicMock(content=content)),
        )

    @pytest.mark.asyncio
    async def test_valid_llm_response_parsed(self, analysis_request, valid_llm_json):
        analyzer = self._make_analyzer_with_mock_chain(valid_llm_json)
        with self._patch_langchain():
            result = await analyzer.analyze(analysis_request)
        assert isinstance(result, AlertAnalysis)
        assert "Shellshock" in result.summary
        assert len(result.investigation_steps) == 3

    @pytest.mark.asyncio
    async def test_chain_called_with_messages(self, analysis_request, valid_llm_json):
        analyzer = self._make_analyzer_with_mock_chain(valid_llm_json)
        with self._patch_langchain():
            await analyzer.analyze(analysis_request)
        analyzer._chain.ainvoke.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_result_has_all_required_fields(self, analysis_request, valid_llm_json):
        analyzer = self._make_analyzer_with_mock_chain(valid_llm_json)
        with self._patch_langchain():
            result = await analyzer.analyze(analysis_request)
        d = result.to_dict()
        assert "summary" in d
        assert "risk_assessment" in d
        assert "investigation_steps" in d
        assert "recommended_actions" in d

    @pytest.mark.asyncio
    async def test_markdown_fenced_json_stripped(self, analysis_request, valid_llm_json):
        fenced = f"```json\n{valid_llm_json}\n```"
        analyzer = self._make_analyzer_with_mock_chain(fenced)
        with self._patch_langchain():
            result = await analyzer.analyze(analysis_request)
        assert isinstance(result, AlertAnalysis)

    @pytest.mark.asyncio
    async def test_list_field_as_string_normalised(self, analysis_request):
        malformed = json.dumps({
            "summary": "A threat was detected.",
            "risk_assessment": "High risk.",
            "investigation_steps": "Check logs",       # string, not list
            "recommended_actions": ["Isolate host"],
        })
        analyzer = self._make_analyzer_with_mock_chain(malformed)
        with self._patch_langchain():
            result = await analyzer.analyze(analysis_request)
        assert isinstance(result.investigation_steps, list)


# ===========================================================================
# AlertAnalyzer – failure / fallback paths
# ===========================================================================


class TestAlertAnalyzerFallback:
    def _patch_langchain(self):
        import app.services.llm_analyzer as mod
        return patch.multiple(
            mod,
            _LANGCHAIN_AVAILABLE=True,
            HumanMessage=MagicMock(side_effect=lambda content: MagicMock(content=content)),
        )

    def _make_failing_analyzer(self, error: Exception, max_retries: int = 1) -> AlertAnalyzer:
        """Return an AlertAnalyzer whose chain always raises *error*."""
        analyzer = AlertAnalyzer(dry_run=False, max_retries=max_retries)
        mock_chain = AsyncMock()
        mock_chain.ainvoke = AsyncMock(side_effect=error)
        analyzer._chain = mock_chain
        analyzer._system_msg = MagicMock()
        return analyzer

    @pytest.mark.asyncio
    async def test_json_parse_error_falls_back(self, analysis_request):
        analyzer = AlertAnalyzer(dry_run=False)
        mock_chain = AsyncMock()
        mock_chain.ainvoke = AsyncMock(return_value="not valid json at all!!!")
        analyzer._chain = mock_chain
        analyzer._system_msg = MagicMock()
        with self._patch_langchain():
            result = await analyzer.analyze(analysis_request)
        assert isinstance(result, AlertAnalysis)

    @pytest.mark.asyncio
    async def test_pydantic_validation_error_falls_back(self, analysis_request):
        # Valid JSON but missing required fields
        bad_json = json.dumps({"summary": "Only summary, nothing else"})
        analyzer = AlertAnalyzer(dry_run=False)
        mock_chain = AsyncMock()
        mock_chain.ainvoke = AsyncMock(return_value=bad_json)
        analyzer._chain = mock_chain
        analyzer._system_msg = MagicMock()
        with self._patch_langchain():
            result = await analyzer.analyze(analysis_request)
        # Should fall back to heuristic
        assert isinstance(result, AlertAnalysis)
        assert len(result.investigation_steps) > 0

    @pytest.mark.asyncio
    async def test_connection_error_falls_back(self, analysis_request):
        analyzer = self._make_failing_analyzer(ConnectionError("Ollama unreachable"))
        with self._patch_langchain():
            result = await analyzer.analyze(analysis_request)
        assert isinstance(result, AlertAnalysis)

    @pytest.mark.asyncio
    async def test_retry_exhausted_falls_back(self, analysis_request):
        analyzer = self._make_failing_analyzer(
            TimeoutError("Timeout"), max_retries=3
        )
        with self._patch_langchain():
            result = await analyzer.analyze(analysis_request)
        # Heuristic fallback still produces a valid result
        assert isinstance(result, AlertAnalysis)
        # Verify all retries were attempted
        assert analyzer._chain.ainvoke.await_count == 3

    @pytest.mark.asyncio
    async def test_retry_succeeds_on_second_attempt(self, analysis_request, valid_llm_json):
        analyzer = AlertAnalyzer(dry_run=False, max_retries=2)
        mock_chain = AsyncMock()
        # First call fails, second succeeds
        mock_chain.ainvoke = AsyncMock(
            side_effect=[RuntimeError("Transient error"), valid_llm_json]
        )
        analyzer._chain = mock_chain
        analyzer._system_msg = MagicMock()
        with self._patch_langchain():
            result = await analyzer.analyze(analysis_request)
        assert isinstance(result, AlertAnalysis)
        assert "Shellshock" in result.summary
        assert analyzer._chain.ainvoke.await_count == 2

    @pytest.mark.asyncio
    async def test_empty_llm_response_falls_back(self, analysis_request):
        analyzer = AlertAnalyzer(dry_run=False)
        mock_chain = AsyncMock()
        mock_chain.ainvoke = AsyncMock(return_value="")
        analyzer._chain = mock_chain
        analyzer._system_msg = MagicMock()
        with self._patch_langchain():
            result = await analyzer.analyze(analysis_request)
        assert isinstance(result, AlertAnalysis)


# ===========================================================================
# AlertAnalyzer._parse_llm_output
# ===========================================================================


class TestParseLlmOutput:
    @pytest.fixture(autouse=True)
    def analyzer(self):
        self.a = AlertAnalyzer(dry_run=True)

    def _req(self) -> AlertAnalysisRequest:
        return AlertAnalysisRequest(
            timestamp="2024-01-01T00:00:00Z",
            source="splunk",
            severity="high",
            alert_name="Test",
        )

    def _valid_dict(self) -> dict:
        return {
            "summary": "A test.",
            "risk_assessment": "High risk.",
            "investigation_steps": ["Check logs"],
            "recommended_actions": ["Isolate host"],
        }

    def test_parses_valid_json(self):
        result = self.a._parse_llm_output(json.dumps(self._valid_dict()), self._req())
        assert isinstance(result, AlertAnalysis)

    def test_strips_leading_trailing_whitespace(self):
        raw = "  \n" + json.dumps(self._valid_dict()) + "\n  "
        result = self.a._parse_llm_output(raw, self._req())
        assert isinstance(result, AlertAnalysis)

    def test_strips_markdown_code_fence(self):
        raw = "```json\n" + json.dumps(self._valid_dict()) + "\n```"
        result = self.a._parse_llm_output(raw, self._req())
        assert isinstance(result, AlertAnalysis)

    def test_strips_plain_code_fence(self):
        raw = "```\n" + json.dumps(self._valid_dict()) + "\n```"
        result = self.a._parse_llm_output(raw, self._req())
        assert isinstance(result, AlertAnalysis)

    def test_invalid_json_returns_heuristic(self):
        result = self.a._parse_llm_output("{ bad json", self._req())
        assert isinstance(result, AlertAnalysis)

    def test_string_list_normalised(self):
        data = {**self._valid_dict(), "investigation_steps": "Single string step"}
        result = self.a._parse_llm_output(json.dumps(data), self._req())
        assert isinstance(result.investigation_steps, list)

    def test_null_list_normalised(self):
        data = {**self._valid_dict(), "recommended_actions": None}
        result = self.a._parse_llm_output(json.dumps(data), self._req())
        # Falls back to heuristic because recommended_actions would be empty
        assert isinstance(result, AlertAnalysis)


# ===========================================================================
# create_analyzer factory
# ===========================================================================


class TestCreateAnalyzer:
    def test_returns_analyzer_instance(self):
        analyzer = create_analyzer(dry_run=True)
        assert isinstance(analyzer, AlertAnalyzer)

    def test_dry_run_flag_set(self):
        analyzer = create_analyzer(dry_run=True)
        assert analyzer.dry_run is True

    def test_settings_loaded_when_available(self):
        """
        When app.core.config is importable (conftest loads it), settings
        should populate the analyzer's fields.
        """
        analyzer = create_analyzer(dry_run=True)
        # Default model from settings is "llama3"
        assert analyzer.model == "llama3"


# ===========================================================================
# Integration-style tests
# ===========================================================================


class TestEndToEnd:
    """Smoke tests for the full pipeline in dry_run mode."""

    @pytest.mark.asyncio
    async def test_critical_alert_produces_isolation_action(self):
        req = AlertAnalysisRequest.from_dicts(alert={
            "timestamp": "2024-06-01T00:00:00Z",
            "source": "splunk",
            "severity": "critical",
            "alert_name": "Ransomware Execution Detected",
            "host": "finance-server-01",
            "user": "SYSTEM",
        })
        analyzer = AlertAnalyzer(dry_run=True)
        result = await analyzer.analyze(req)
        actions_text = " ".join(result.recommended_actions).lower()
        steps_text = " ".join(result.investigation_steps).lower()
        assert "isolate" in actions_text or "isolate" in steps_text

    @pytest.mark.asyncio
    async def test_full_request_with_mitre_matches(self):
        req = AlertAnalysisRequest.from_dicts(
            alert={
                "timestamp": "2024-06-01T00:00:00Z",
                "source": "elasticsearch",
                "severity": "high",
                "alert_name": "Lateral Movement via PsExec",
                "host": "domain-controller",
                "user": "CORP\\admin",
            },
            mitre_matches=[
                {
                    "technique_id": "T1021",
                    "technique_name": "Remote Services",
                    "tactic": "Lateral Movement",
                    "tactic_id": "TA0008",
                    "confidence": 0.88,
                    "mapping_method": "keyword",
                    "rationale": "Matched: remote, services",
                }
            ],
        )
        analyzer = AlertAnalyzer(dry_run=True)
        result = await analyzer.analyze(req)
        d = result.to_dict()
        assert all(k in d for k in ["summary", "risk_assessment", "investigation_steps", "recommended_actions"])

    @pytest.mark.asyncio
    async def test_output_schema_exact_match(self):
        """Verify to_dict() keys match the required output schema exactly."""
        req = AlertAnalysisRequest.from_dicts(alert={
            "timestamp": "2024-06-01T00:00:00Z",
            "source": "wazuh",
            "severity": "medium",
            "alert_name": "SSH Brute Force",
        })
        analyzer = AlertAnalyzer(dry_run=True)
        result = await analyzer.analyze(req)
        output = result.to_dict()
        assert set(output.keys()) == {
            "summary",
            "risk_assessment",
            "investigation_steps",
            "recommended_actions",
        }
        assert isinstance(output["summary"], str)
        assert isinstance(output["risk_assessment"], str)
        assert isinstance(output["investigation_steps"], list)
        assert isinstance(output["recommended_actions"], list)
        assert len(output["investigation_steps"]) > 0
        assert len(output["recommended_actions"]) > 0
