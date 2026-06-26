"""
Unit Tests – Log Normalization Engine
======================================
Tests cover:
- Output schema validation (NormalizedAlert)
- Timestamp coercion (_parse_timestamp)
- Severity mapping (_normalize_severity)
- SplunkParser field mapping
- ElasticsearchParser field mapping (ECS + generic)
- WazuhParser field mapping
- NormalizerRegistry registration / lookup
- LogNormalizer.normalize() and normalize_batch()
- Error propagation and unknown-source handling
- Extensibility: registering a custom parser at runtime

Run with::

    pytest tests/test_normalizer.py -v
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import pytest
from pydantic import ValidationError

# Path is configured by conftest.py (backend/ is on sys.path)
from app.services.normalizer import (
    BaseParser,
    ElasticsearchParser,
    LogNormalizer,
    NormalizedAlert,
    NormalizationError,
    NormalizerRegistry,
    SplunkParser,
    UnknownSourceError,
    WazuhParser,
    _normalize_severity,
    _parse_timestamp,
    default_registry,
)


# ===========================================================================
# Fixtures – representative raw alert payloads
# ===========================================================================


@pytest.fixture()
def splunk_notable() -> Dict[str, Any]:
    """Minimal Splunk ES notable event as returned by SplunkConnector."""
    return {
        "_time": "2024-06-01T12:34:56+00:00",
        "rule_name": "Brute-Force Login Detected",
        "urgency": "high",
        "src": "10.0.0.5",
        "dest": "webserver-01",
        "user": "jdoe",
        "event_id": "evt-001",
    }


@pytest.fixture()
def splunk_minimal() -> Dict[str, Any]:
    """Splunk notable with the bare minimum of fields."""
    return {"rule_name": "Minimal Alert"}


@pytest.fixture()
def es_ecs_alert() -> Dict[str, Any]:
    """Elasticsearch / Kibana SIEM alert in ECS format."""
    return {
        "@timestamp": "2024-06-01T15:00:00.000Z",
        "signal": {
            "rule": {
                "name": "Lateral Movement via PsExec",
                "severity": "critical",
            }
        },
        "host": {"name": "dc-01"},
        "user": {"name": "CORP\\admin"},
        "severity": "critical",
    }


@pytest.fixture()
def es_generic_alert() -> Dict[str, Any]:
    """Elasticsearch alert without ECS structure."""
    return {
        "timestamp": "2024-06-01T09:00:00",
        "message": "Anomalous outbound traffic",
        "severity": "medium",
        "host": "endpoint-42",
        "user": "bob",
    }


@pytest.fixture()
def es_numeric_severity_alert() -> Dict[str, Any]:
    """Elasticsearch alert with numeric severity (0-100 ECS style)."""
    return {
        "@timestamp": "2024-06-02T08:00:00Z",
        "kibana.alert.severity": 80,
        "alert_name": "High-severity rule hit",
    }


@pytest.fixture()
def wazuh_alert() -> Dict[str, Any]:
    """Representative Wazuh alert dict."""
    return {
        "timestamp": "2024-06-01T18:22:10.123+0000",
        "rule": {
            "description": "Shellshock attack detected",
            "id": "31166",
            "level": 14,
        },
        "agent": {"id": "001", "name": "linux-agent-01", "ip": "192.168.1.10"},
        "data": {"srcuser": "apache", "dstuser": "root"},
    }


@pytest.fixture()
def wazuh_minimal() -> Dict[str, Any]:
    """Wazuh alert with minimum fields."""
    return {"rule": {"description": "Minimal Wazuh Alert", "level": 7}}


# ===========================================================================
# _parse_timestamp
# ===========================================================================


class TestParseTimestamp:
    def test_datetime_with_tz(self):
        dt = datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
        result = _parse_timestamp(dt)
        assert "2024-01-15" in result

    def test_datetime_without_tz_becomes_utc(self):
        dt = datetime(2024, 1, 15, 10, 30, 0)
        result = _parse_timestamp(dt)
        parsed = datetime.fromisoformat(result)
        assert parsed.tzinfo is not None

    def test_unix_epoch_seconds(self):
        epoch = 1717243200.0  # 2024-06-01T12:00:00Z
        result = _parse_timestamp(epoch)
        assert "2024-06-01" in result

    def test_unix_epoch_milliseconds(self):
        epoch_ms = 1717243200000  # same moment in ms
        result = _parse_timestamp(epoch_ms)
        assert "2024-06-01" in result

    def test_iso_string_with_z(self):
        result = _parse_timestamp("2024-06-01T12:34:56Z")
        assert "2024-06-01" in result
        assert "12:34:56" in result

    def test_iso_string_with_offset(self):
        result = _parse_timestamp("2024-06-01T12:34:56+05:30")
        assert "2024-06-01" in result  # date may shift due to UTC conversion

    def test_none_returns_current_time(self):
        result = _parse_timestamp(None)
        parsed = datetime.fromisoformat(result)
        assert (datetime.now(timezone.utc) - parsed).total_seconds() < 5

    def test_unparseable_string_returns_fallback(self):
        result = _parse_timestamp("not-a-date")
        parsed = datetime.fromisoformat(result)
        assert (datetime.now(timezone.utc) - parsed).total_seconds() < 5


# ===========================================================================
# _normalize_severity
# ===========================================================================


class TestNormalizeSeverity:
    @pytest.mark.parametrize(
        "raw, expected",
        [
            ("critical", "critical"),
            ("CRITICAL", "critical"),
            ("high", "high"),
            ("HIGH", "high"),
            ("medium", "medium"),
            ("low", "low"),
            ("informational", "informational"),
            ("info", "informational"),
            ("warning", "medium"),
            ("error", "high"),
            ("14", "critical"),
            ("8", "medium"),
            ("3", "low"),
            (None, "medium"),
            ("totally_unknown", "medium"),  # default fallback
        ],
    )
    def test_mapping(self, raw, expected):
        assert _normalize_severity(raw) == expected


# ===========================================================================
# NormalizedAlert schema
# ===========================================================================


class TestNormalizedAlert:
    def _make(self, **overrides) -> Dict[str, Any]:
        base = {
            "timestamp": "2024-06-01T12:00:00+00:00",
            "source": "splunk",
            "severity": "high",
            "alert_name": "Test Alert",
            "host": "host-01",
            "user": "alice",
            "raw_log": '{"key": "value"}',
        }
        base.update(overrides)
        return base

    def test_valid_alert(self):
        alert = NormalizedAlert(**self._make())
        assert alert.severity == "high"
        assert alert.source == "splunk"

    def test_severity_is_canonicalised(self):
        alert = NormalizedAlert(**self._make(severity="HIGH"))
        assert alert.severity == "high"

    def test_invalid_severity_raises(self):
        with pytest.raises(ValidationError, match="Invalid severity"):
            NormalizedAlert(**self._make(severity="super_critical_plus"))

    def test_invalid_timestamp_raises(self):
        with pytest.raises(ValidationError):
            NormalizedAlert(**self._make(timestamp="not-a-timestamp"))

    def test_blank_source_raises(self):
        with pytest.raises(ValidationError):
            NormalizedAlert(**self._make(source=""))

    def test_blank_alert_name_raises(self):
        with pytest.raises(ValidationError):
            NormalizedAlert(**self._make(alert_name=""))

    def test_invalid_raw_log_json_raises(self):
        with pytest.raises(ValidationError, match="raw_log must be a valid JSON"):
            NormalizedAlert(**self._make(raw_log="not-json"))

    def test_to_dict_matches_schema(self):
        alert = NormalizedAlert(**self._make())
        d = alert.to_dict()
        assert set(d.keys()) == {
            "timestamp", "source", "severity", "alert_name", "host", "user", "raw_log"
        }

    def test_source_lowercased(self):
        alert = NormalizedAlert(**self._make(source="SPLUNK"))
        assert alert.source == "splunk"

    def test_default_host_and_user(self):
        data = self._make()
        data.pop("host", None)
        data.pop("user", None)
        alert = NormalizedAlert(**data)
        assert alert.host == "unknown"
        assert alert.user == "unknown"


# ===========================================================================
# SplunkParser
# ===========================================================================


class TestSplunkParser:
    @pytest.fixture(autouse=True)
    def parser(self):
        self.p = SplunkParser()

    def test_full_notable(self, splunk_notable):
        alert = self.p.parse(splunk_notable)
        assert alert.source == "splunk"
        assert alert.alert_name == "Brute-Force Login Detected"
        assert alert.severity == "high"
        assert alert.host == "webserver-01"
        assert alert.user == "jdoe"
        assert "2024-06-01" in alert.timestamp

    def test_minimal_fields(self, splunk_minimal):
        alert = self.p.parse(splunk_minimal)
        assert alert.alert_name == "Minimal Alert"
        assert alert.severity == "medium"   # default
        assert alert.host == "unknown"
        assert alert.user == "unknown"

    def test_urgency_critical(self):
        alert = self.p.parse({"rule_name": "X", "urgency": "critical"})
        assert alert.severity == "critical"

    def test_urgency_informational(self):
        alert = self.p.parse({"rule_name": "X", "urgency": "informational"})
        assert alert.severity == "informational"

    def test_fallback_to_search_name(self):
        alert = self.p.parse({"search_name": "My Search", "urgency": "low"})
        assert alert.alert_name == "My Search"

    def test_raw_log_is_serialized_dict(self, splunk_notable):
        alert = self.p.parse(splunk_notable)
        data = json.loads(alert.raw_log)
        assert data["rule_name"] == splunk_notable["rule_name"]

    def test_non_dict_raises_normalization_error(self):
        with pytest.raises(NormalizationError):
            self.p.parse("not a dict")  # type: ignore[arg-type]

    def test_src_used_as_host_when_dest_missing(self):
        alert = self.p.parse({"rule_name": "X", "src": "attacker-pc"})
        assert alert.host == "attacker-pc"

    def test_src_user_fallback(self):
        alert = self.p.parse({"rule_name": "X", "src_user": "charlie"})
        assert alert.user == "charlie"


# ===========================================================================
# ElasticsearchParser
# ===========================================================================


class TestElasticsearchParser:
    @pytest.fixture(autouse=True)
    def parser(self):
        self.p = ElasticsearchParser()

    def test_ecs_format(self, es_ecs_alert):
        alert = self.p.parse(es_ecs_alert)
        assert alert.source == "elasticsearch"
        assert alert.alert_name == "Lateral Movement via PsExec"
        assert alert.severity == "critical"
        assert alert.host == "dc-01"
        assert "admin" in alert.user

    def test_generic_format(self, es_generic_alert):
        alert = self.p.parse(es_generic_alert)
        assert alert.alert_name == "Anomalous outbound traffic"
        assert alert.severity == "medium"
        assert alert.host == "endpoint-42"
        assert alert.user == "bob"

    def test_numeric_severity_high(self, es_numeric_severity_alert):
        alert = self.p.parse(es_numeric_severity_alert)
        # 80 → decile 8 → critical
        assert alert.severity == "critical"

    def test_numeric_severity_low(self):
        alert = self.p.parse({"@timestamp": "2024-01-01T00:00:00Z", "message": "X",
                               "kibana.alert.severity": 20})
        assert alert.severity == "low"

    def test_at_timestamp_parsed(self, es_ecs_alert):
        alert = self.p.parse(es_ecs_alert)
        assert "2024-06-01" in alert.timestamp

    def test_host_as_plain_string(self):
        raw = {"message": "Alert", "host": "plain-host", "@timestamp": "2024-01-01T00:00:00Z"}
        alert = self.p.parse(raw)
        assert alert.host == "plain-host"

    def test_user_as_plain_string(self):
        raw = {"message": "Alert", "user": "frank", "@timestamp": "2024-01-01T00:00:00Z"}
        alert = self.p.parse(raw)
        assert alert.user == "frank"

    def test_raw_log_contains_original_fields(self, es_ecs_alert):
        alert = self.p.parse(es_ecs_alert)
        raw = json.loads(alert.raw_log)
        assert "@timestamp" in raw

    def test_missing_all_optional_fields(self):
        alert = self.p.parse({})
        assert alert.alert_name == "Elasticsearch Alert"
        assert alert.host == "unknown"
        assert alert.user == "unknown"


# ===========================================================================
# WazuhParser
# ===========================================================================


class TestWazuhParser:
    @pytest.fixture(autouse=True)
    def parser(self):
        self.p = WazuhParser()

    def test_full_alert(self, wazuh_alert):
        alert = self.p.parse(wazuh_alert)
        assert alert.source == "wazuh"
        assert alert.alert_name == "Shellshock attack detected"
        assert alert.severity == "critical"   # level 14
        assert alert.host == "linux-agent-01"
        assert alert.user == "apache"

    def test_minimal_alert(self, wazuh_minimal):
        alert = self.p.parse(wazuh_minimal)
        assert alert.alert_name == "Minimal Wazuh Alert"
        assert alert.severity == "low"   # level 7 → low (Wazuh levels 4-7 = low)

    def test_level_0_is_informational(self):
        alert = self.p.parse({"rule": {"description": "X", "level": 0}})
        assert alert.severity == "informational"

    def test_level_15_is_critical(self):
        alert = self.p.parse({"rule": {"description": "X", "level": 15}})
        assert alert.severity == "critical"

    def test_level_4_is_low(self):
        alert = self.p.parse({"rule": {"description": "X", "level": 4}})
        assert alert.severity == "low"

    def test_level_12_is_high(self):
        alert = self.p.parse({"rule": {"description": "X", "level": 12}})
        assert alert.severity == "high"

    def test_agent_ip_fallback_host(self):
        raw = {"rule": {"description": "X", "level": 5},
               "agent": {"ip": "10.0.0.1"}}
        alert = self.p.parse(raw)
        assert alert.host == "10.0.0.1"

    def test_dstuser_fallback(self):
        raw = {"rule": {"description": "X", "level": 5},
               "data": {"dstuser": "root"}}
        alert = self.p.parse(raw)
        assert alert.user == "root"

    def test_windows_event_user_extraction(self):
        raw = {
            "rule": {"description": "Windows Login", "level": 9},
            "data": {"win": {"eventdata": {"subjectUserName": "DOMAIN\\winuser"}}},
        }
        alert = self.p.parse(raw)
        assert "winuser" in alert.user

    def test_raw_log_is_valid_json(self, wazuh_alert):
        alert = self.p.parse(wazuh_alert)
        data = json.loads(alert.raw_log)
        assert data["rule"]["level"] == 14

    def test_missing_rule_key(self):
        alert = self.p.parse({})
        assert alert.alert_name == "Wazuh Alert"


# ===========================================================================
# NormalizerRegistry
# ===========================================================================


class TestNormalizerRegistry:
    def test_default_registry_has_three_sources(self):
        assert set(default_registry.registered_sources) >= {"splunk", "elasticsearch", "wazuh"}

    def test_get_splunk_parser(self):
        parser = default_registry.get("splunk")
        assert isinstance(parser, SplunkParser)

    def test_get_wazuh_parser(self):
        parser = default_registry.get("wazuh")
        assert isinstance(parser, WazuhParser)

    def test_get_elasticsearch_parser(self):
        parser = default_registry.get("elasticsearch")
        assert isinstance(parser, ElasticsearchParser)

    def test_case_insensitive_lookup(self):
        parser = default_registry.get("SPLUNK")
        assert isinstance(parser, SplunkParser)

    def test_unknown_source_raises(self):
        with pytest.raises(UnknownSourceError):
            default_registry.get("nonexistent_source")

    def test_register_custom_parser(self):
        registry = NormalizerRegistry()

        class MyParser(BaseParser):
            source_name = "my_tool"

            def _parse(self, raw):
                return NormalizedAlert(
                    timestamp=_parse_timestamp(None),
                    source="my_tool",
                    severity="low",
                    alert_name=raw.get("name", "X"),
                    host="unknown",
                    user="unknown",
                    raw_log=self._to_raw_log(raw),
                )

        registry.register(MyParser)
        assert "my_tool" in registry.registered_sources
        parser = registry.get("my_tool")
        alert = parser.parse({"name": "Custom Alert"})
        assert alert.alert_name == "Custom Alert"

    def test_auto_register_decorator(self):
        registry = NormalizerRegistry()

        @registry.auto_register
        class DecoParser(BaseParser):
            source_name = "deco_tool"

            def _parse(self, raw):
                return NormalizedAlert(
                    timestamp=_parse_timestamp(None),
                    source="deco_tool",
                    severity="informational",
                    alert_name="Deco Alert",
                    host="unknown",
                    user="unknown",
                    raw_log=self._to_raw_log(raw),
                )

        assert "deco_tool" in registry.registered_sources

    def test_registering_parser_without_source_name_raises(self):
        class BadParser(BaseParser):
            def _parse(self, raw):
                pass

        registry = NormalizerRegistry()
        with pytest.raises(TypeError, match="source_name"):
            registry.register(BadParser)

    def test_overwrite_existing_parser(self):
        registry = NormalizerRegistry()

        class ParserV1(BaseParser):
            source_name = "tool"

            def _parse(self, raw):
                return NormalizedAlert(
                    timestamp=_parse_timestamp(None), source="tool",
                    severity="low", alert_name="V1", host="unknown",
                    user="unknown", raw_log="{}"
                )

        class ParserV2(BaseParser):
            source_name = "tool"

            def _parse(self, raw):
                return NormalizedAlert(
                    timestamp=_parse_timestamp(None), source="tool",
                    severity="high", alert_name="V2", host="unknown",
                    user="unknown", raw_log="{}"
                )

        registry.register(ParserV1)
        registry.register(ParserV2)
        alert = registry.get("tool").parse({})
        assert alert.alert_name == "V2"


# ===========================================================================
# LogNormalizer (façade)
# ===========================================================================


class TestLogNormalizer:
    @pytest.fixture(autouse=True)
    def normalizer(self):
        self.n = LogNormalizer()

    def test_normalize_splunk(self, splunk_notable):
        alert = self.n.normalize("splunk", splunk_notable)
        assert isinstance(alert, NormalizedAlert)
        assert alert.source == "splunk"

    def test_normalize_elasticsearch(self, es_ecs_alert):
        alert = self.n.normalize("elasticsearch", es_ecs_alert)
        assert alert.source == "elasticsearch"

    def test_normalize_wazuh(self, wazuh_alert):
        alert = self.n.normalize("wazuh", wazuh_alert)
        assert alert.source == "wazuh"

    def test_unknown_source_raises(self):
        with pytest.raises(UnknownSourceError):
            self.n.normalize("phantom_siem", {})

    def test_supported_sources(self):
        sources = self.n.supported_sources
        assert "splunk" in sources
        assert "elasticsearch" in sources
        assert "wazuh" in sources

    def test_normalize_batch_all_valid(self, splunk_notable):
        alerts = self.n.normalize_batch("splunk", [splunk_notable, splunk_notable])
        assert len(alerts) == 2

    def test_normalize_batch_skip_errors(self):
        raws = [
            {"rule_name": "Good Alert"},
            "not-a-dict",   # will fail
            {"rule_name": "Also Good"},
        ]
        alerts = self.n.normalize_batch("splunk", raws, skip_errors=True)  # type: ignore[arg-type]
        assert len(alerts) == 2

    def test_normalize_batch_reraise_on_error(self):
        raws = [{"rule_name": "Good"}, "bad"]  # type: ignore[list-item]
        with pytest.raises(NormalizationError):
            self.n.normalize_batch("splunk", raws, skip_errors=False)

    def test_normalize_batch_empty_list(self):
        alerts = self.n.normalize_batch("wazuh", [])
        assert alerts == []

    def test_custom_registry_injection(self):
        registry = NormalizerRegistry()

        class StubParser(BaseParser):
            source_name = "stub"

            def _parse(self, raw):
                return NormalizedAlert(
                    timestamp=_parse_timestamp(None),
                    source="stub",
                    severity="informational",
                    alert_name="Stub",
                    host="unknown",
                    user="unknown",
                    raw_log="{}",
                )

        registry.register(StubParser)
        n = LogNormalizer(registry=registry)
        alert = n.normalize("stub", {})
        assert alert.source == "stub"

    def test_output_schema_keys(self, wazuh_alert):
        alert = self.n.normalize("wazuh", wazuh_alert)
        d = alert.to_dict()
        expected_keys = {"timestamp", "source", "severity", "alert_name", "host", "user", "raw_log"}
        assert set(d.keys()) == expected_keys

    def test_raw_log_is_valid_json_in_output(self, splunk_notable):
        alert = self.n.normalize("splunk", splunk_notable)
        parsed = json.loads(alert.raw_log)
        assert isinstance(parsed, dict)


# ===========================================================================
# Integration-style tests (multi-source round-trips)
# ===========================================================================


class TestEndToEndRoundTrip:
    """Smoke tests that exercise the full pipeline for each source."""

    def test_splunk_round_trip(self):
        raw = {
            "_time": "2024-07-04T00:00:00Z",
            "rule_name": "Ransomware Detected",
            "urgency": "critical",
            "dest": "fileserver-01",
            "user": "SYSTEM",
        }
        alert = LogNormalizer().normalize("splunk", raw)
        assert alert.severity == "critical"
        assert alert.host == "fileserver-01"
        assert json.loads(alert.raw_log)["rule_name"] == "Ransomware Detected"

    def test_elasticsearch_round_trip(self):
        raw = {
            "@timestamp": "2024-07-04T00:00:00Z",
            "signal": {"rule": {"name": "Credential Dumping", "severity": "high"}},
            "host": {"name": "wks-10"},
            "user": {"name": "attacker"},
        }
        alert = LogNormalizer().normalize("elasticsearch", raw)
        assert alert.severity == "high"
        assert alert.host == "wks-10"
        assert alert.user == "attacker"

    def test_wazuh_round_trip(self):
        raw = {
            "timestamp": "2024-07-04T00:00:00.000+0000",
            "rule": {"description": "SSH brute force", "level": 10},
            "agent": {"name": "sshd-box", "ip": "172.16.0.1"},
            "data": {"srcuser": "root"},
        }
        alert = LogNormalizer().normalize("wazuh", raw)
        assert alert.severity == "medium"  # level 10 → medium
        assert alert.host == "sshd-box"
        assert alert.user == "root"

    def test_batch_multi_source(self):
        n = LogNormalizer()
        alerts = []
        alerts += n.normalize_batch("splunk", [{"rule_name": "S1"}, {"rule_name": "S2"}])
        alerts += n.normalize_batch("wazuh", [{"rule": {"description": "W1", "level": 5}}])
        assert len(alerts) == 3
        sources = {a.source for a in alerts}
        assert sources == {"splunk", "wazuh"}
