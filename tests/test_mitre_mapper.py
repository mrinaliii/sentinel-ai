"""
Unit Tests – MITRE ATT&CK Mapping Service
===========================================
All tests use the local STIX fixture (tests/fixtures/attack_fixture.json)
so no network access is required.

Fixture techniques:
  T1059      Command and Scripting Interpreter  → Execution
  T1059.001  PowerShell (sub-technique of T1059) → Execution
  T1003      OS Credential Dumping              → Credential Access
  T1046      Network Service Discovery          → Discovery
  T1021      Remote Services                    → Lateral Movement
  T1055      Process Injection                  → Privilege Escalation + Defense Evasion

Run with::

    pytest tests/test_mitre_mapper.py -v
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import List
from unittest.mock import patch

import pytest

# conftest.py loads the app.services.mitre_mapper module directly;
# it also loads app.core.logging and app.core.exceptions from file.
from app.services.mitre_mapper import (
    AttackIndex,
    AttackLoader,
    BaseMatchStrategy,
    ExactIDStrategy,
    KeywordStrategy,
    MappingResult,
    MitreMapper,
    TechniqueMatch,
    TFIDFStrategy,
    _Technique,
    _tokenize,
    get_mapper,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "attack_fixture.json"


def _build_mapper() -> MitreMapper:
    """Return a loaded mapper backed by the local fixture."""
    mapper = MitreMapper(stix_path=FIXTURE_PATH)
    mapper.load()
    return mapper


def _build_index() -> AttackIndex:
    loader = AttackLoader(stix_path=FIXTURE_PATH)
    techniques = loader.load()
    return AttackIndex(techniques)


# ===========================================================================
# _tokenize
# ===========================================================================


class TestTokenize:
    def test_basic_split(self):
        assert "powershell" in _tokenize("PowerShell command executed")

    def test_stop_words_removed(self):
        tokens = _tokenize("the alert is using system")
        assert "the" not in tokens
        assert "alert" not in tokens

    def test_short_tokens_removed(self):
        tokens = _tokenize("ab cd xyz execution")
        assert "ab" not in tokens
        assert "cd" not in tokens
        assert "xyz" in tokens

    def test_numbers_included(self):
        tokens = _tokenize("encoded base64 T1059")
        assert "t1059" in tokens  # regex matches alphanumeric

    def test_case_insensitive(self):
        tokens = _tokenize("LSASS MEMORY DUMP")
        assert "lsass" in tokens
        assert "memory" in tokens

    def test_empty_string(self):
        assert _tokenize("") == []

    def test_punctuation_stripped(self):
        tokens = _tokenize("credential-dumping, lsass.exe!")
        assert "credential" in tokens
        assert "dumping" in tokens
        assert "lsass" in tokens


# ===========================================================================
# AttackLoader
# ===========================================================================


class TestAttackLoader:
    def test_loads_from_local_file(self):
        loader = AttackLoader(stix_path=FIXTURE_PATH)
        techniques = loader.load()
        assert len(techniques) >= 6  # 6 non-revoked in fixture

    def test_revoked_techniques_excluded(self):
        loader = AttackLoader(stix_path=FIXTURE_PATH)
        techniques = loader.load()
        ids = [t.technique_id for t in techniques]
        assert "T9999" not in ids

    def test_technique_fields_populated(self):
        loader = AttackLoader(stix_path=FIXTURE_PATH)
        techs = {t.technique_id: t for t in loader.load()}

        t1059 = techs["T1059"]
        assert t1059.name == "Command and Scripting Interpreter"
        assert "Execution" in t1059.tactic_names
        assert "TA0002" in t1059.tactic_ids
        assert t1059.is_subtechnique is False

    def test_subtechnique_parsed(self):
        loader = AttackLoader(stix_path=FIXTURE_PATH)
        techs = {t.technique_id: t for t in loader.load()}

        sub = techs["T1059.001"]
        assert sub.is_subtechnique is True
        assert sub.parent_id == "T1059"
        assert sub.parent_name == "Command and Scripting Interpreter"

    def test_multi_tactic_technique(self):
        loader = AttackLoader(stix_path=FIXTURE_PATH)
        techs = {t.technique_id: t for t in loader.load()}

        t1055 = techs["T1055"]
        assert len(t1055.tactic_names) == 2
        tactic_names = set(t1055.tactic_names)
        assert "Privilege Escalation" in tactic_names
        assert "Defense Evasion" in tactic_names

    def test_missing_file_raises(self):
        loader = AttackLoader(stix_path="/nonexistent/path.json")
        with pytest.raises(FileNotFoundError):
            loader.load()

    def test_no_technique_id_skipped(self, tmp_path):
        """Objects without a mitre-attack external reference should be skipped."""
        bundle = {
            "objects": [
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--noid",
                    "name": "No ID technique",
                    "description": "Missing external ID",
                    "kill_chain_phases": [],
                    "external_references": [],
                    "revoked": False,
                }
            ]
        }
        f = tmp_path / "bundle.json"
        f.write_text(json.dumps(bundle))
        loader = AttackLoader(stix_path=f)
        techniques = loader.load()
        assert all(t.technique_id != "" for t in techniques)


# ===========================================================================
# AttackIndex
# ===========================================================================


class TestAttackIndex:
    @pytest.fixture(autouse=True)
    def index(self):
        self.idx = _build_index()

    def test_len_equals_technique_count(self):
        assert len(self.idx) == 6  # fixture has 6 non-revoked

    def test_get_by_id_exact(self):
        tech = self.idx.get_by_id("T1059")
        assert tech is not None
        assert tech.technique_id == "T1059"

    def test_get_by_id_case_insensitive(self):
        assert self.idx.get_by_id("t1059") is not None
        assert self.idx.get_by_id("T1059") is not None

    def test_get_by_id_missing_returns_none(self):
        assert self.idx.get_by_id("T9999") is None

    def test_inverted_index_populated(self):
        # "powershell" should map to T1059.001 (and maybe T1059)
        candidates = self.idx.candidate_ids_for_tokens(["powershell"])
        assert "T1059.001" in candidates

    def test_candidate_ids_union(self):
        c1 = self.idx.candidate_ids_for_tokens(["powershell"])
        c2 = self.idx.candidate_ids_for_tokens(["lsass"])
        union = self.idx.candidate_ids_for_tokens(["powershell", "lsass"])
        assert c1 | c2 == union

    def test_tfidf_score_positive_for_match(self):
        score = self.idx.tfidf_score(["powershell", "command"], "T1059.001")
        assert score > 0

    def test_tfidf_score_zero_for_no_overlap(self):
        score = self.idx.tfidf_score(["unrelated", "xyz123word"], "T1059.001")
        assert score == 0.0

    def test_tfidf_score_bounded(self):
        score = self.idx.tfidf_score(
            _tokenize("PowerShell is a powerful interactive command-line interface"),
            "T1059.001",
        )
        assert 0.0 <= score <= 1.0

    def test_rare_token_has_higher_idf(self):
        # 'lsass' should appear in fewer techniques than 'command'
        lsass_idf = self.idx._idf.get("lsass", 0)
        cmd_idf = self.idx._idf.get("command", 0)
        # lsass is more discriminating (higher IDF)
        assert lsass_idf >= cmd_idf

    def test_all_techniques_returns_list(self):
        techs = self.idx.all_techniques()
        assert isinstance(techs, list)
        assert len(techs) == 6


# ===========================================================================
# ExactIDStrategy
# ===========================================================================


class TestExactIDStrategy:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.strategy = ExactIDStrategy()
        self.idx = _build_index()

    def test_detects_bare_id(self):
        results = self.strategy.score("Triggered rule T1059", [], self.idx)
        assert any(tid == "T1059" for tid, _, _ in results)

    def test_detects_subtechnique_id(self):
        results = self.strategy.score("Alert: T1059.001 PowerShell detected", [], self.idx)
        ids = [tid for tid, _, _ in results]
        assert "T1059.001" in ids

    def test_confidence_is_one(self):
        results = self.strategy.score("T1003 OS Credential Dumping", [], self.idx)
        for _, conf, _ in results:
            assert conf == 1.0

    def test_unknown_id_excluded(self):
        results = self.strategy.score("T9898 T0000 in alert", [], self.idx)
        # Neither T9898 nor T0000 exist in fixture
        assert len(results) == 0

    def test_deduplicates_same_id(self):
        results = self.strategy.score("T1059 T1059 T1059", [], self.idx)
        ids = [tid for tid, _, _ in results]
        assert ids.count("T1059") == 1

    def test_case_insensitive_match(self):
        results = self.strategy.score("technique t1059", [], self.idx)
        ids = [tid for tid, _, _ in results]
        assert "T1059" in ids


# ===========================================================================
# KeywordStrategy
# ===========================================================================


class TestKeywordStrategy:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.strategy = KeywordStrategy()
        self.idx = _build_index()

    def test_powershell_matches_t1059_001(self):
        tokens = _tokenize("PowerShell encoded command execution")
        results = self.strategy.score("", tokens, self.idx)
        ids = [r[0] for r in results]
        assert "T1059.001" in ids

    def test_lsass_matches_t1003(self):
        tokens = _tokenize("LSASS memory dump credentials")
        results = self.strategy.score("", tokens, self.idx)
        ids = [r[0] for r in results]
        assert "T1003" in ids

    def test_confidence_in_range(self):
        tokens = _tokenize("PowerShell execution script")
        results = self.strategy.score("", tokens, self.idx)
        for _, conf, _ in results:
            assert 0.0 <= conf <= 1.0

    def test_empty_tokens_returns_empty(self):
        results = self.strategy.score("", [], self.idx)
        assert results == []

    def test_rationale_contains_tokens(self):
        tokens = _tokenize("PowerShell encoded")
        results = self.strategy.score("", tokens, self.idx)
        # Find T1059.001 result
        for tid, _, rationale in results:
            if tid == "T1059.001":
                assert "powershell" in rationale.lower() or "encoded" in rationale.lower()
                break

    def test_no_match_for_irrelevant_text(self):
        tokens = _tokenize("xyzzy quux foobarbaz")
        results = self.strategy.score("", tokens, self.idx)
        assert results == []


# ===========================================================================
# TFIDFStrategy
# ===========================================================================


class TestTFIDFStrategy:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.strategy = TFIDFStrategy()
        self.idx = _build_index()

    def test_scores_returned_for_relevant_query(self):
        tokens = _tokenize("PowerShell command interpreter scripting")
        results = self.strategy.score("", tokens, self.idx)
        assert len(results) > 0

    def test_score_higher_for_better_match(self):
        specific_tokens = _tokenize("LSASS dump credentials SAM database DCSync")
        generic_tokens = _tokenize("some vague generic text")

        specific = {r[0]: r[1] for r in self.strategy.score("", specific_tokens, self.idx)}
        generic = {r[0]: r[1] for r in self.strategy.score("", generic_tokens, self.idx)}

        t1003_specific = specific.get("T1003", 0.0)
        t1003_generic = generic.get("T1003", 0.0)
        assert t1003_specific >= t1003_generic

    def test_all_scores_in_range(self):
        tokens = _tokenize("remote SSH RDP SMB lateral movement accounts")
        for _, conf, _ in self.strategy.score("", tokens, self.idx):
            assert 0.0 <= conf <= 1.0

    def test_empty_returns_empty(self):
        assert self.strategy.score("", [], self.idx) == []


# ===========================================================================
# MitreMapper
# ===========================================================================


class TestMitreMapper:
    @pytest.fixture(autouse=True)
    def mapper(self):
        self.m = _build_mapper()

    def test_is_loaded(self):
        assert self.m.is_loaded

    def test_technique_count(self):
        assert self.m.technique_count == 6

    # ── map_alert ────────────────────────────────────────────────────────

    def test_returns_mapping_result(self):
        result = self.m.map_alert("PowerShell execution detected")
        assert isinstance(result, MappingResult)

    def test_matches_are_sorted_by_confidence_desc(self):
        result = self.m.map_alert("PowerShell command scripting execution")
        confs = [m.confidence for m in result.matches]
        assert confs == sorted(confs, reverse=True)

    def test_exact_id_in_text_gets_top_confidence(self):
        result = self.m.map_alert("Detected T1003 OS Credential Dumping via LSASS")
        assert result.top_match is not None
        assert result.top_match.technique_id == "T1003"
        assert result.top_match.confidence == 1.0
        assert result.top_match.mapping_method == "exact_id"

    def test_powershell_alert_maps_to_execution(self):
        result = self.m.map_alert("Encoded PowerShell command executed via cmd")
        ids = [m.technique_id for m in result.matches]
        assert "T1059.001" in ids or "T1059" in ids

    def test_tactic_field_populated(self):
        result = self.m.map_alert("T1003")
        assert result.top_match.tactic == "Credential Access"
        assert result.top_match.tactic_id == "TA0006"

    def test_tactic_id_field_populated(self):
        result = self.m.map_alert("T1046 network port scanning")
        ids_hit = {m.technique_id for m in result.matches}
        assert "T1046" in ids_hit
        disc = next(m for m in result.matches if m.technique_id == "T1046")
        assert disc.tactic_id == "TA0007"

    def test_max_results_respected(self):
        result = self.m.map_alert("execution credential discovery lateral movement injection", max_results=2)
        assert len(result.matches) <= 2

    def test_min_confidence_filters_low_scores(self):
        result = self.m.map_alert("PowerShell", min_confidence=0.99)
        for m in result.matches:
            assert m.confidence >= 0.99

    def test_empty_text_returns_empty_matches(self):
        result = self.m.map_alert("")
        assert result.matches == []

    def test_irrelevant_text_returns_no_or_few_matches(self):
        result = self.m.map_alert("xyzzy foobarbaz nothing here", min_confidence=0.5)
        assert len(result.matches) == 0

    def test_subtechnique_fields_set_correctly(self):
        result = self.m.map_alert("T1059.001 PowerShell")
        sub = next((m for m in result.matches if m.technique_id == "T1059.001"), None)
        assert sub is not None
        assert sub.sub_technique_id == "T1059.001"
        assert sub.sub_technique is not None

    def test_parent_technique_fields_not_set_as_sub(self):
        result = self.m.map_alert("T1059")
        parent = next((m for m in result.matches if m.technique_id == "T1059"), None)
        assert parent is not None
        assert parent.sub_technique_id is None

    def test_unloaded_mapper_raises(self):
        m = MitreMapper(stix_path=FIXTURE_PATH)
        with pytest.raises(RuntimeError, match="load()"):
            m.map_alert("anything")

    def test_rationale_present(self):
        result = self.m.map_alert("LSASS memory credential dump")
        for m in result.matches:
            assert m.rationale is not None and len(m.rationale) > 0

    # ── get_technique ─────────────────────────────────────────────────────

    def test_get_technique_by_id(self):
        tech = self.m.get_technique("T1003")
        assert tech is not None
        assert tech.name == "OS Credential Dumping"

    def test_get_technique_missing_returns_none(self):
        assert self.m.get_technique("T9999") is None

    def test_get_technique_case_insensitive(self):
        assert self.m.get_technique("t1003") is not None

    # ── search_techniques ─────────────────────────────────────────────────

    def test_search_returns_list(self):
        matches = self.m.search_techniques("credential dumping LSASS")
        assert isinstance(matches, list)
        assert all(isinstance(m, TechniqueMatch) for m in matches)

    # ── add_strategy ─────────────────────────────────────────────────────

    def test_custom_strategy_integrated(self):
        class AlwaysMatchT1021(BaseMatchStrategy):
            name = "always_t1021"

            def score(self, alert_text, query_tokens, index):
                return [("T1021", 0.99, "custom rule hit")]

        self.m.add_strategy(AlwaysMatchT1021())
        result = self.m.map_alert("totally unrelated text xyzzy qwerty 12345")
        ids = [m.technique_id for m in result.matches]
        # Custom strategy injects T1021 with 0.99 confidence (above default min=0.20)
        assert "T1021" in ids

    def test_custom_strategy_best_score_wins(self):
        """When custom strategy returns a higher score than built-ins, it should win."""
        class HighScorer(BaseMatchStrategy):
            name = "high_scorer"

            def score(self, alert_text, query_tokens, index):
                # Always propose T1055 with perfect confidence
                return [("T1055", 1.0, "high scorer override")]

        self.m.add_strategy(HighScorer())
        result = self.m.map_alert("T1055 process injection detected")
        t1055 = next(m for m in result.matches if m.technique_id == "T1055")
        # Exact ID strategy also scores 1.0; custom may tie but not lower
        assert t1055.confidence == 1.0


# ===========================================================================
# TechniqueMatch schema
# ===========================================================================


class TestTechniqueMatch:
    def _make(self, **overrides):
        base = dict(
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter",
            tactic="Execution",
            tactic_id="TA0002",
            confidence=0.85,
            mapping_method="keyword",
        )
        base.update(overrides)
        return base

    def test_valid_match(self):
        m = TechniqueMatch(**self._make())
        assert m.technique_id == "T1059"
        assert m.tactic_id == "TA0002"

    def test_confidence_out_of_range_raises(self):
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            TechniqueMatch(**self._make(confidence=1.5))

    def test_to_dict_has_required_keys(self):
        m = TechniqueMatch(**self._make())
        d = m.to_dict()
        assert {"technique_id", "technique_name", "tactic", "tactic_id", "confidence"} <= d.keys()

    def test_optional_fields_default_none(self):
        m = TechniqueMatch(**self._make())
        assert m.sub_technique is None
        assert m.sub_technique_id is None
        assert m.rationale is None


# ===========================================================================
# MappingResult
# ===========================================================================


class TestMappingResult:
    def test_top_match_returns_first(self):
        m1 = TechniqueMatch(
            technique_id="T1059", technique_name="X", tactic="Execution",
            tactic_id="TA0002", confidence=0.9, mapping_method="keyword"
        )
        m2 = TechniqueMatch(
            technique_id="T1003", technique_name="Y", tactic="Credential Access",
            tactic_id="TA0006", confidence=0.7, mapping_method="tfidf"
        )
        result = MappingResult(alert_text="test", matches=[m1, m2])
        assert result.top_match.technique_id == "T1059"

    def test_top_match_none_when_empty(self):
        result = MappingResult(alert_text="test")
        assert result.top_match is None


# ===========================================================================
# get_mapper singleton
# ===========================================================================


class TestGetMapper:
    def test_returns_mapper_instance(self):
        import app.services.mitre_mapper as mm_mod
        mm_mod._default_mapper = None   # reset singleton
        mapper = get_mapper(stix_path=FIXTURE_PATH)
        assert isinstance(mapper, MitreMapper)

    def test_singleton_not_reloaded(self):
        import app.services.mitre_mapper as mm_mod
        mm_mod._default_mapper = None
        m1 = get_mapper(stix_path=FIXTURE_PATH)
        m2 = get_mapper(stix_path=FIXTURE_PATH)
        assert m1 is m2

    def test_force_refresh_creates_new(self):
        import app.services.mitre_mapper as mm_mod
        mm_mod._default_mapper = None
        m1 = get_mapper(stix_path=FIXTURE_PATH)
        m2 = get_mapper(stix_path=FIXTURE_PATH, force_refresh=True)
        assert m1 is not m2


# ===========================================================================
# Integration – end-to-end
# ===========================================================================


class TestEndToEnd:
    """
    Smoke tests that exercise full pipeline with realistic alert text.
    """

    @pytest.fixture(autouse=True)
    def mapper(self):
        self.m = _build_mapper()

    def test_ransomware_alert_maps_to_execution(self):
        alert = "PowerShell download cradle executes encoded payload"
        result = self.m.map_alert(alert)
        tactic_names = {m.tactic for m in result.matches}
        assert "Execution" in tactic_names

    def test_credential_theft_alert(self):
        alert = "LSASS.exe accessed by mimikatz - credentials dumped from memory SAM database"
        result = self.m.map_alert(alert, max_results=3)
        ids = {m.technique_id for m in result.matches}
        assert "T1003" in ids

    def test_lateral_movement_alert(self):
        alert = "Remote SSH login from unusual IP - possible lateral movement via valid account"
        result = self.m.map_alert(alert)
        ids = {m.technique_id for m in result.matches}
        assert "T1021" in ids

    def test_multi_technique_alert(self):
        alert = "T1059 T1003 T1055 combined attack chain detected"
        result = self.m.map_alert(alert, max_results=5)
        ids = {m.technique_id for m in result.matches}
        # All three should be matched via exact ID
        assert {"T1059", "T1003", "T1055"}.issubset(ids)

    def test_output_schema_complete(self):
        result = self.m.map_alert("T1046 network port scan")
        match = result.top_match
        assert match.technique_id
        assert match.technique_name
        assert match.tactic
        assert match.tactic_id
        assert 0.0 <= match.confidence <= 1.0
        assert match.mapping_method
