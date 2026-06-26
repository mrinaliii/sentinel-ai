"""
MITRE ATT&CK Mapping Service
==============================
Maps alert text to MITRE ATT&CK techniques via three complementary strategies:

  1. **Exact / prefix keyword matching** – O(1) lookup via an inverted index
     built from technique names, aliases, and tactic names at load time.

  2. **TF-IDF token scoring** – weighted token-overlap that rewards rare,
     discriminating terms and penalises common stop-words.

  3. **Technique-ID extraction** – regex scan for ``Txxxx`` / ``Txxxx.xxx``
     patterns already present in the alert text.

Data source
-----------
ATT&CK is distributed as a STIX 2.1 bundle (JSON).  This service supports:

  * **Remote fetch** – downloads the latest Enterprise bundle from GitHub
    (MITRE CTI repo) on first use, then caches it to disk.
  * **Local file** – pass an explicit ``stix_path`` to ``AttackLoader`` to
    use an on-disk bundle (useful in air-gapped environments or tests).

Architecture
------------
::

    AttackLoader          – downloads / caches / parses the STIX bundle
        └──▶ AttackIndex  – builds inverted-index + tf-idf corpus at init
                 └──▶ MitreMapper.map_alert()  – public façade, returns
                              List[TechniqueMatch] sorted by confidence desc

Performance
-----------
* The index is built **once** at startup (``AttackLoader.build_index()``).
* All lookups run in O(k·log N) where k = unique tokens in the query and
  N = number of technique entries (~700 for Enterprise ATT&CK v15).
* Token sets and inverted-index dicts are stored in plain Python dicts for
  cache-line efficiency; no external DB or vector store required.

Adding a new match strategy
---------------------------
Subclass ``BaseMatchStrategy`` and implement ``score()``, then append an
instance to ``MitreMapper._strategies``.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import re
import time
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar, Dict, FrozenSet, List, Optional, Set, Tuple

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Default STIX bundle – MITRE CTI Enterprise ATT&CK v15.1
_DEFAULT_STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/"
    "enterprise-attack.json"
)

# Local cache path (relative to this file's parent package)
_CACHE_DIR = Path(os.environ.get("MITRE_CACHE_DIR", Path(__file__).parent / ".mitre_cache"))
_CACHE_FILE = _CACHE_DIR / "enterprise-attack.json"

# Stop-words filtered from TF-IDF scoring
_STOP_WORDS: FrozenSet[str] = frozenset(
    {
        "a", "an", "the", "and", "or", "of", "in", "on", "at", "to", "for",
        "is", "are", "was", "be", "by", "with", "from", "that", "this", "it",
        "as", "via", "using", "use", "uses", "used", "can", "may", "alert",
        "event", "log", "rule", "detected", "detection", "system", "windows",
        "linux", "macos", "host", "user", "file", "process", "network", "access",
        "attack", "threat", "security", "malicious", "suspicious", "activity",
    }
)

# Technique-ID regex  (T1234 or T1234.567)
_TECHNIQUE_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)

# Confidence thresholds for mapping_method label
_CONFIDENCE_HIGH = 0.70
_CONFIDENCE_MED  = 0.40


# ---------------------------------------------------------------------------
# Output models
# ---------------------------------------------------------------------------


class TechniqueMatch(BaseModel):
    """A single ATT&CK technique match returned by the mapper."""

    technique_id: str = Field(..., description="ATT&CK technique ID, e.g. 'T1059'")
    technique_name: str = Field(..., description="Human-readable technique name")
    tactic: str = Field(..., description="Primary tactic name, e.g. 'Execution'")
    tactic_id: str = Field(..., description="Tactic ID, e.g. 'TA0002'")
    sub_technique: Optional[str] = Field(None, description="Sub-technique name if applicable")
    sub_technique_id: Optional[str] = Field(None, description="Sub-technique ID if applicable")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score [0, 1]")
    mapping_method: str = Field(..., description="exact_id | keyword | tfidf")
    rationale: Optional[str] = Field(None, description="Token overlap / match explanation")

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class MappingResult(BaseModel):
    """Full mapping result for a single alert."""

    alert_text: str
    matches: List[TechniqueMatch] = Field(default_factory=list)
    mapped_at: float = Field(default_factory=time.time)

    @property
    def top_match(self) -> Optional[TechniqueMatch]:
        return self.matches[0] if self.matches else None


# ---------------------------------------------------------------------------
# Internal dataclass for indexed techniques
# ---------------------------------------------------------------------------


@dataclass
class _Technique:
    """Parsed ATT&CK technique entry held in memory."""

    technique_id: str           # e.g. "T1059"
    name: str                   # e.g. "Command and Scripting Interpreter"
    description: str
    tactic_names: List[str]     # may contain multiple tactics
    tactic_ids: List[str]
    is_subtechnique: bool
    parent_id: Optional[str]    # e.g. "T1059" for "T1059.001"
    parent_name: Optional[str]
    aliases: List[str] = field(default_factory=list)

    # Token bag built at index time
    token_set: FrozenSet[str] = field(default_factory=frozenset)

    @property
    def primary_tactic(self) -> str:
        return self.tactic_names[0] if self.tactic_names else "unknown"

    @property
    def primary_tactic_id(self) -> str:
        return self.tactic_ids[0] if self.tactic_ids else "TA0000"


# ---------------------------------------------------------------------------
# STIX loader
# ---------------------------------------------------------------------------


class AttackLoader:
    """
    Downloads (or reads from disk) the MITRE ATT&CK STIX bundle and parses
    it into ``_Technique`` records.

    Parameters
    ----------
    stix_path : str or Path, optional
        Explicit path to an on-disk STIX JSON file.  If *None*, the bundle
        is fetched from the MITRE CTI GitHub repo and cached locally.
    force_refresh : bool
        If *True*, re-download even if a cache file exists.
    """

    # Tactic short-name → (display name, tactic ID) map
    _TACTIC_MAP: ClassVar[Dict[str, Tuple[str, str]]] = {
        "initial-access":        ("Initial Access",       "TA0001"),
        "execution":             ("Execution",            "TA0002"),
        "persistence":           ("Persistence",          "TA0003"),
        "privilege-escalation":  ("Privilege Escalation", "TA0004"),
        "defense-evasion":       ("Defense Evasion",      "TA0005"),
        "credential-access":     ("Credential Access",    "TA0006"),
        "discovery":             ("Discovery",            "TA0007"),
        "lateral-movement":      ("Lateral Movement",     "TA0008"),
        "collection":            ("Collection",           "TA0009"),
        "command-and-control":   ("Command and Control",  "TA0011"),
        "exfiltration":          ("Exfiltration",         "TA0010"),
        "impact":                ("Impact",               "TA0040"),
        "resource-development":  ("Resource Development", "TA0042"),
        "reconnaissance":        ("Reconnaissance",       "TA0043"),
    }

    def __init__(
        self,
        stix_path: Optional[str | Path] = None,
        force_refresh: bool = False,
    ) -> None:
        self._stix_path = Path(stix_path) if stix_path else None
        self._force_refresh = force_refresh

    def load(self) -> List[_Technique]:
        """Return a list of parsed ``_Technique`` objects."""
        bundle = self._get_bundle()
        return self._parse_bundle(bundle)

    # ── private ──────────────────────────────────────────────────────────────

    def _get_bundle(self) -> Dict[str, Any]:
        if self._stix_path:
            logger.info("mitre_loader_reading_file", path=str(self._stix_path))
            with open(self._stix_path, encoding="utf-8") as fh:
                return json.load(fh)

        if not self._force_refresh and _CACHE_FILE.exists():
            logger.info("mitre_loader_using_cache", path=str(_CACHE_FILE))
            with open(_CACHE_FILE, encoding="utf-8") as fh:
                return json.load(fh)

        return self._download_and_cache()

    def _download_and_cache(self) -> Dict[str, Any]:
        import urllib.request

        logger.info("mitre_loader_downloading", url=_DEFAULT_STIX_URL)
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)

        tmp = _CACHE_FILE.with_suffix(".tmp")
        try:
            urllib.request.urlretrieve(_DEFAULT_STIX_URL, tmp)
            with open(tmp, encoding="utf-8") as fh:
                bundle = json.load(fh)
            # Validate minimal structure before committing cache
            if "objects" not in bundle:
                raise ValueError("Downloaded bundle has no 'objects' key")
            tmp.replace(_CACHE_FILE)
            logger.info("mitre_loader_download_complete", size=_CACHE_FILE.stat().st_size)
        finally:
            if tmp.exists():
                tmp.unlink(missing_ok=True)
        return bundle

    def _parse_bundle(self, bundle: Dict[str, Any]) -> List[_Technique]:
        """Extract attack-pattern objects and resolve their phase→tactic mappings."""
        objects = bundle.get("objects", [])

        # Build id → relationship mapping for sub-techniques
        # STIX sub-technique parent is encoded as a 'subtechnique-of' relationship
        parent_of: Dict[str, str] = {}  # child_stix_id → parent_stix_id
        for obj in objects:
            if (
                obj.get("type") == "relationship"
                and obj.get("relationship_type") == "subtechnique-of"
            ):
                parent_of[obj["source_ref"]] = obj["target_ref"]

        # Build stix_id → (technique_id, name) for parent lookup
        id_to_tech: Dict[str, Tuple[str, str]] = {}
        for obj in objects:
            if obj.get("type") == "attack-pattern" and not obj.get("revoked"):
                ext = obj.get("external_references", [])
                for ref in ext:
                    if ref.get("source_name") == "mitre-attack":
                        id_to_tech[obj["id"]] = (ref["external_id"], obj["name"])
                        break

        techniques: List[_Technique] = []
        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue

            # ── Extract technique ID ──────────────────────────────────────
            technique_id: Optional[str] = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref["external_id"]
                    break
            if not technique_id:
                continue

            is_sub = "." in technique_id
            parent_id: Optional[str] = None
            parent_name: Optional[str] = None
            if is_sub:
                parent_stix = parent_of.get(obj["id"])
                if parent_stix and parent_stix in id_to_tech:
                    parent_id, parent_name = id_to_tech[parent_stix]

            # ── Resolve tactics ──────────────────────────────────────────
            tactic_names: List[str] = []
            tactic_ids: List[str] = []
            for phase in obj.get("kill_chain_phases", []):
                if phase.get("kill_chain_name") == "mitre-attack":
                    phase_name = phase["phase_name"]
                    tactic_display, tactic_id = self._TACTIC_MAP.get(
                        phase_name, (phase_name.replace("-", " ").title(), "TA0000")
                    )
                    tactic_names.append(tactic_display)
                    tactic_ids.append(tactic_id)

            techniques.append(
                _Technique(
                    technique_id=technique_id,
                    name=obj["name"],
                    description=obj.get("description", ""),
                    tactic_names=tactic_names or ["Unknown"],
                    tactic_ids=tactic_ids or ["TA0000"],
                    is_subtechnique=is_sub,
                    parent_id=parent_id,
                    parent_name=parent_name,
                    aliases=obj.get("x_mitre_aliases", []),
                )
            )

        logger.info("mitre_loader_parsed", count=len(techniques))
        return techniques


# ---------------------------------------------------------------------------
# Search index
# ---------------------------------------------------------------------------


def _tokenize(text: str) -> List[str]:
    """Lower-case, split on non-alpha, remove stop-words."""
    tokens = re.findall(r"[a-z][a-z0-9]*", text.lower())
    return [t for t in tokens if t not in _STOP_WORDS and len(t) > 2]


class AttackIndex:
    """
    In-memory search index over a corpus of ATT&CK techniques.

    Structures built at ``__init__`` time:

    * ``_by_id``          – ``Dict[str, _Technique]``  (exact ID lookup)
    * ``_inverted``       – ``Dict[str, Set[str]]``     (token → set of technique IDs)
    * ``_idf``            – ``Dict[str, float]``        (IDF weight per token)
    * ``_tech_tokens``    – ``Dict[str, FrozenSet[str]]`` (technique ID → token set)

    Time complexity:  O(V) build, O(k) lookup where k = query token count.
    """

    def __init__(self, techniques: List[_Technique]) -> None:
        self._techniques: List[_Technique] = techniques
        self._by_id: Dict[str, _Technique] = {}
        self._inverted: Dict[str, Set[str]] = defaultdict(set)
        self._idf: Dict[str, float] = {}
        self._tech_tokens: Dict[str, FrozenSet[str]] = {}

        self._build(techniques)

    # ── build ──────────────────────────────────────────────────────────────

    def _build(self, techniques: List[_Technique]) -> None:
        N = len(techniques)
        doc_freq: Dict[str, int] = defaultdict(int)

        for tech in techniques:
            self._by_id[tech.technique_id.upper()] = tech

            # Collect all text signals for this technique
            corpus_parts = [
                tech.name,
                tech.description[:500],           # cap description for speed
                " ".join(tech.tactic_names),
                " ".join(tech.aliases),
            ]
            if tech.parent_name:
                corpus_parts.append(tech.parent_name)

            tokens = _tokenize(" ".join(corpus_parts))
            token_set = frozenset(tokens)

            tech.token_set = token_set
            self._tech_tokens[tech.technique_id] = token_set

            for tok in token_set:
                self._inverted[tok].add(tech.technique_id)
                doc_freq[tok] += 1

        # Pre-compute IDF:  log((N + 1) / (df + 1)) + 1
        for tok, df in doc_freq.items():
            self._idf[tok] = math.log((N + 1) / (df + 1)) + 1.0

        logger.info(
            "mitre_index_built",
            techniques=len(techniques),
            unique_tokens=len(self._inverted),
        )

    # ── lookups ────────────────────────────────────────────────────────────

    def get_by_id(self, technique_id: str) -> Optional[_Technique]:
        """Exact lookup by ATT&CK ID (case-insensitive)."""
        return self._by_id.get(technique_id.upper())

    def candidate_ids_for_tokens(self, tokens: List[str]) -> Set[str]:
        """Return technique IDs whose index contains at least one query token."""
        result: Set[str] = set()
        for tok in tokens:
            result |= self._inverted.get(tok, set())
        return result

    def tfidf_score(self, query_tokens: List[str], technique_id: str) -> float:
        """
        Cosine-similarity-like TF-IDF score between query and technique corpus.

        Uses binary TF (term present/absent) for simplicity and speed.
        """
        tech_tokens = self._tech_tokens.get(technique_id, frozenset())
        if not tech_tokens:
            return 0.0

        query_set = frozenset(query_tokens)
        overlap = query_set & tech_tokens

        if not overlap:
            return 0.0

        # Weighted overlap / normalised by query vector magnitude
        overlap_weight = sum(self._idf.get(t, 1.0) for t in overlap)
        query_weight = sum(self._idf.get(t, 1.0) for t in query_set) or 1.0

        return min(overlap_weight / query_weight, 1.0)

    def all_techniques(self) -> List[_Technique]:
        return self._techniques

    def __len__(self) -> int:
        return len(self._techniques)


# ---------------------------------------------------------------------------
# Match strategies (Strategy pattern)
# ---------------------------------------------------------------------------


class BaseMatchStrategy(ABC):
    """Abstract base for a technique-matching strategy."""

    name: ClassVar[str]

    @abstractmethod
    def score(
        self,
        alert_text: str,
        query_tokens: List[str],
        index: AttackIndex,
    ) -> List[Tuple[str, float, str]]:
        """
        Return a list of ``(technique_id, confidence, rationale)`` tuples.
        Confidence must be in [0, 1].
        """


class ExactIDStrategy(BaseMatchStrategy):
    """
    Scan alert text for literal ATT&CK IDs (e.g. 'T1059' or 'T1059.003').
    Yields confidence = 1.0 for each found ID that exists in the index.
    """

    name = "exact_id"

    def score(
        self,
        alert_text: str,
        query_tokens: List[str],
        index: AttackIndex,
    ) -> List[Tuple[str, float, str]]:
        found = _TECHNIQUE_ID_RE.findall(alert_text)
        results = []
        for raw_id in dict.fromkeys(t.upper() for t in found):  # deduplicate, preserve order
            if index.get_by_id(raw_id):
                results.append((raw_id, 1.0, f"Explicit technique ID '{raw_id}' found in alert text"))
        return results


class KeywordStrategy(BaseMatchStrategy):
    """
    Match alert tokens against the inverted index.
    Scores by fraction of a technique's token set that overlaps the query.
    """

    name = "keyword"

    def score(
        self,
        alert_text: str,
        query_tokens: List[str],
        index: AttackIndex,
    ) -> List[Tuple[str, float, str]]:
        if not query_tokens:
            return []

        candidates = index.candidate_ids_for_tokens(query_tokens)
        query_set = frozenset(query_tokens)
        results = []

        for tid in candidates:
            tech = index.get_by_id(tid)
            if not tech:
                continue
            overlap = query_set & tech.token_set
            if not overlap:
                continue
            # Score = fraction of technique tokens matched / query size
            recall = len(overlap) / max(len(tech.token_set), 1)
            precision = len(overlap) / max(len(query_set), 1)
            f1 = 2 * recall * precision / max(recall + precision, 1e-9)
            rationale = f"Matched tokens: {', '.join(sorted(overlap)[:8])}"
            results.append((tid, round(f1, 4), rationale))

        return results


class TFIDFStrategy(BaseMatchStrategy):
    """
    TF-IDF weighted token overlap.  Rewards discriminating terms that appear
    in few techniques, giving higher confidence for precise matches.
    """

    name = "tfidf"

    def score(
        self,
        alert_text: str,
        query_tokens: List[str],
        index: AttackIndex,
    ) -> List[Tuple[str, float, str]]:
        if not query_tokens:
            return []

        candidates = index.candidate_ids_for_tokens(query_tokens)
        results = []

        for tid in candidates:
            sc = index.tfidf_score(query_tokens, tid)
            if sc > 0:
                results.append((tid, round(sc, 4), f"TF-IDF score={sc:.4f}"))

        return results


# ---------------------------------------------------------------------------
# Public mapper façade
# ---------------------------------------------------------------------------


class MitreMapper:
    """
    Public façade for MITRE ATT&CK alert mapping.

    Usage::

        mapper = MitreMapper()
        mapper.load()                          # build index (call once)

        results = mapper.map_alert(
            "Detected PowerShell executing encoded command T1059.001",
            max_results=5,
            min_confidence=0.30,
        )
        for m in results.matches:
            print(m.technique_id, m.tactic, m.confidence)

    Parameters
    ----------
    stix_path : str or Path, optional
        Path to a local STIX JSON bundle.  If omitted, bundle is fetched
        from MITRE CTI GitHub and cached at ``~/.mitre_cache/``.
    force_refresh : bool
        Re-download the STIX bundle even if a local cache exists.
    """

    def __init__(
        self,
        stix_path: Optional[str | Path] = None,
        force_refresh: bool = False,
    ) -> None:
        self._loader = AttackLoader(stix_path=stix_path, force_refresh=force_refresh)
        self._index: Optional[AttackIndex] = None

        # Strategy pipeline – order matters: exact ID first, then graded scoring
        self._strategies: List[BaseMatchStrategy] = [
            ExactIDStrategy(),
            KeywordStrategy(),
            TFIDFStrategy(),
        ]

    # ── lifecycle ──────────────────────────────────────────────────────────

    def load(self) -> "MitreMapper":
        """
        Download / parse the ATT&CK STIX bundle and build the search index.
        Call this once at application startup.  Returns ``self`` for chaining.
        """
        techniques = self._loader.load()
        self._index = AttackIndex(techniques)
        logger.info("mitre_mapper_ready", techniques=len(techniques))
        return self

    @property
    def is_loaded(self) -> bool:
        return self._index is not None

    @property
    def technique_count(self) -> int:
        return len(self._index) if self._index else 0

    # ── main API ────────────────────────────────────────────────────────────

    def map_alert(
        self,
        alert_text: str,
        *,
        max_results: int = 5,
        min_confidence: float = 0.20,
    ) -> MappingResult:
        """
        Match *alert_text* against the ATT&CK technique corpus.

        Parameters
        ----------
        alert_text :
            Free-form text: alert name, description, rule text, raw log, etc.
        max_results :
            Maximum number of ``TechniqueMatch`` entries to return.
        min_confidence :
            Drop matches below this threshold (0.0–1.0).

        Returns
        -------
        MappingResult
            Contains an ordered list of ``TechniqueMatch`` objects (highest
            confidence first).

        Raises
        ------
        RuntimeError
            If ``load()`` has not been called yet.
        """
        if self._index is None:
            raise RuntimeError("MitreMapper.load() must be called before map_alert().")

        query_tokens = _tokenize(alert_text)

        # ── Collect scores from all strategies ────────────────────────────
        # best_scores: technique_id → (best_confidence, method, rationale)
        best_scores: Dict[str, Tuple[float, str, str]] = {}

        for strategy in self._strategies:
            for tid, conf, rationale in strategy.score(alert_text, query_tokens, self._index):
                existing = best_scores.get(tid)
                if existing is None or conf > existing[0]:
                    best_scores[tid] = (conf, strategy.name, rationale)

        # ── Filter, sort, build output ────────────────────────────────────
        ranked = sorted(best_scores.items(), key=lambda kv: kv[1][0], reverse=True)
        matches: List[TechniqueMatch] = []

        for tid, (conf, method, rationale) in ranked:
            if conf < min_confidence:
                break
            if len(matches) >= max_results:
                break

            tech = self._index.get_by_id(tid)
            if not tech:
                continue

            matches.append(
                TechniqueMatch(
                    technique_id=tech.technique_id,
                    technique_name=tech.name,
                    tactic=tech.primary_tactic,
                    tactic_id=tech.primary_tactic_id,
                    sub_technique=tech.name if tech.is_subtechnique else None,
                    sub_technique_id=tech.technique_id if tech.is_subtechnique else None,
                    confidence=conf,
                    mapping_method=method,
                    rationale=rationale,
                )
            )

        logger.info(
            "mitre_mapper_alert_mapped",
            matched=len(matches),
            top_confidence=matches[0].confidence if matches else 0.0,
        )
        return MappingResult(alert_text=alert_text, matches=matches)

    def get_technique(self, technique_id: str) -> Optional[_Technique]:
        """Direct lookup of a technique by ID (e.g. 'T1059')."""
        if self._index is None:
            raise RuntimeError("MitreMapper.load() must be called first.")
        return self._index.get_by_id(technique_id)

    def search_techniques(
        self,
        query: str,
        max_results: int = 10,
        min_confidence: float = 0.15,
    ) -> List[TechniqueMatch]:
        """Convenience wrapper – same as ``map_alert`` but returns the match list directly."""
        return self.map_alert(query, max_results=max_results, min_confidence=min_confidence).matches

    # ── extensibility ─────────────────────────────────────────────────────

    def add_strategy(self, strategy: BaseMatchStrategy) -> None:
        """
        Register a custom match strategy.

        Custom strategies are appended after the built-in ones.
        Scores are merged with the existing best-score-wins logic.
        """
        self._strategies.append(strategy)
        logger.info("mitre_mapper_strategy_added", strategy=strategy.name)


# ---------------------------------------------------------------------------
# Singleton / factory helper
# ---------------------------------------------------------------------------

_default_mapper: Optional[MitreMapper] = None


def get_mapper(
    stix_path: Optional[str | Path] = None,
    force_refresh: bool = False,
) -> MitreMapper:
    """
    Return (and lazily initialise) the module-level singleton ``MitreMapper``.

    In production, call this once at startup::

        from app.services.mitre_mapper import get_mapper
        mapper = get_mapper()          # downloads + indexes on first call
        mapper.load()                  # no-op if already loaded

    In tests, pass ``stix_path`` to point at a local fixture file.
    """
    global _default_mapper
    if _default_mapper is None or force_refresh:
        _default_mapper = MitreMapper(stix_path=stix_path, force_refresh=force_refresh)
    return _default_mapper
