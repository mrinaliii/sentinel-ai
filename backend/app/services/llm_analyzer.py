"""
LangChain Alert Analysis Service
==================================
Uses a local Ollama model (via LangChain's ``ChatOllama``) to produce a
structured security analysis for a normalized alert enriched with MITRE
ATT&CK mappings.

Output schema
-------------
::

    {
      "summary":              str   – concise threat narrative
      "risk_assessment":      str   – severity rationale + business impact
      "investigation_steps":  list  – ordered analyst actions
      "recommended_actions":  list  – remediation / containment steps
    }

Architecture
------------
::

    AlertAnalysisRequest          ← validated input (alert + MITRE matches)
           │
           ▼
    AlertAnalyzer.analyze()
           │
           ├─ _build_prompt()      Jinja-like f-string template → HumanMessage
           │
           ├─ LangChain chain:
           │     ChatOllama  →  JsonOutputParser / PydanticOutputParser
           │     (with retry via RunnableRetry and fallback to stub)
           │
           └─ AlertAnalysis        validated Pydantic output model

Design principles
-----------------
* **Local-first** – ChatOllama points at ``http://localhost:11434`` by default;
  no external API keys required.
* **Structured output** – the chain uses ``PydanticOutputParser`` so the LLM
  response is validated against ``AlertAnalysis`` automatically.
* **Graceful fallback** – if the LLM is unavailable or returns malformed JSON
  the service returns a deterministic heuristic analysis instead of raising.
* **Testable without Ollama** – pass ``dry_run=True`` or inject a custom
  ``llm`` instance to bypass the real model in unit tests.
* **Configurable** – all Ollama parameters (model, temperature, timeout) are
  read from ``app.core.config.settings`` and overridable per call.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# Optional langchain imports – degrade gracefully if not installed
try:
    from langchain_core.messages import HumanMessage, SystemMessage
    _LANGCHAIN_AVAILABLE = True
except ImportError:
    _LANGCHAIN_AVAILABLE = False
    HumanMessage = None   # type: ignore[assignment,misc]
    SystemMessage = None  # type: ignore[assignment,misc]


# ---------------------------------------------------------------------------
# Input / Output schemas
# ---------------------------------------------------------------------------


class MitreMatchInput(BaseModel):
    """Subset of TechniqueMatch fields needed for the prompt."""

    technique_id: str
    technique_name: str
    tactic: str
    tactic_id: str
    confidence: float
    mapping_method: str
    rationale: Optional[str] = None


class AlertAnalysisRequest(BaseModel):
    """Validated input to ``AlertAnalyzer.analyze()``."""

    # Core alert fields (mirrors NormalizedAlert)
    timestamp: str
    source: str
    severity: str
    alert_name: str
    host: str = "unknown"
    user: str = "unknown"
    raw_log: str = "{}"

    # MITRE ATT&CK enrichment (optional – may be empty list)
    mitre_matches: List[MitreMatchInput] = Field(default_factory=list)

    # Optional analyst hint to guide LLM focus
    analyst_hint: Optional[str] = None

    @classmethod
    def from_dicts(
        cls,
        alert: Dict[str, Any],
        mitre_matches: Optional[List[Dict[str, Any]]] = None,
        analyst_hint: Optional[str] = None,
    ) -> "AlertAnalysisRequest":
        """
        Convenience constructor from plain dicts.

        Parameters
        ----------
        alert :
            Output of ``NormalizedAlert.to_dict()``
        mitre_matches :
            List of ``TechniqueMatch.to_dict()`` dicts (or None)
        analyst_hint :
            Optional free-text hint for the LLM
        """
        return cls(
            timestamp=alert.get("timestamp", ""),
            source=alert.get("source", ""),
            severity=alert.get("severity", "medium"),
            alert_name=alert.get("alert_name", "Unknown Alert"),
            host=alert.get("host", "unknown"),
            user=alert.get("user", "unknown"),
            raw_log=alert.get("raw_log", "{}"),
            mitre_matches=[MitreMatchInput(**m) for m in (mitre_matches or [])],
            analyst_hint=analyst_hint,
        )


class AlertAnalysis(BaseModel):
    """
    Validated output of the LLM analysis pipeline.

    This is the exact output schema requested.
    """

    summary: str = Field(
        ...,
        description="Concise 2–4 sentence threat narrative written for a SOC analyst.",
    )
    risk_assessment: str = Field(
        ...,
        description=(
            "Severity rationale explaining why this alert is rated at its current "
            "level, including potential business impact and attacker goals."
        ),
    )
    investigation_steps: List[str] = Field(
        ...,
        min_length=1,
        description="Ordered list of investigation actions for the analyst to perform.",
    )
    recommended_actions: List[str] = Field(
        ...,
        min_length=1,
        description="Ordered list of remediation, containment, or escalation steps.",
    )

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


# ---------------------------------------------------------------------------
# Prompt template
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """You are an expert SOC (Security Operations Center) analyst assistant.
Your task is to analyze a security alert enriched with MITRE ATT&CK threat intelligence
and produce a structured analysis that helps a human analyst triage and respond quickly.

Respond ONLY with a valid JSON object matching this exact schema — no markdown, no extra text:
{{
  "summary": "<2-4 sentence threat narrative>",
  "risk_assessment": "<severity rationale and business impact>",
  "investigation_steps": ["<step 1>", "<step 2>", "..."],
  "recommended_actions": ["<action 1>", "<action 2>", "..."]
}}

Guidelines:
- Be concise and actionable. Avoid generic filler text.
- investigation_steps should be ordered from most urgent to least.
- recommended_actions should cover containment, eradication, and recovery.
- If MITRE techniques are provided, reference them by ID in your analysis.
- Use technical language appropriate for a Tier-2 SOC analyst."""


def _build_human_prompt(req: AlertAnalysisRequest) -> str:
    """Render the alert context into a human message for the LLM."""
    mitre_section = ""
    if req.mitre_matches:
        lines = []
        for m in req.mitre_matches[:5]:  # cap at 5 to stay within context window
            conf_pct = int(m.confidence * 100)
            lines.append(
                f"  • {m.technique_id} – {m.technique_name} "
                f"[{m.tactic}] (confidence: {conf_pct}%)"
            )
            if m.rationale:
                lines.append(f"    Rationale: {m.rationale}")
        mitre_section = "\n\nMITRE ATT&CK Mappings:\n" + "\n".join(lines)

    hint_section = ""
    if req.analyst_hint:
        hint_section = f"\n\nAnalyst Hint: {req.analyst_hint}"

    # Pretty-print raw_log (truncated to 800 chars to avoid token bloat)
    try:
        raw_parsed = json.loads(req.raw_log)
        raw_preview = json.dumps(raw_parsed, indent=2)[:800]
    except (json.JSONDecodeError, TypeError):
        raw_preview = str(req.raw_log)[:800]

    return f"""Analyze the following security alert:

Alert Name  : {req.alert_name}
Source      : {req.source}
Severity    : {req.severity.upper()}
Timestamp   : {req.timestamp}
Host        : {req.host}
User        : {req.user}{mitre_section}{hint_section}

Raw Log (truncated):
{raw_preview}

Produce the JSON analysis now."""


# ---------------------------------------------------------------------------
# Heuristic fallback (used when LLM is unavailable)
# ---------------------------------------------------------------------------

_SEVERITY_RISK: Dict[str, str] = {
    "critical": (
        "This alert is rated CRITICAL. Immediate response is required. "
        "Potential for significant data loss, system compromise, or service disruption."
    ),
    "high": (
        "This alert is rated HIGH severity. Prompt investigation is needed. "
        "Indicates a likely active threat with potential for lateral movement."
    ),
    "medium": (
        "This alert is rated MEDIUM severity. Should be investigated within the "
        "current shift. May indicate reconnaissance or early-stage compromise."
    ),
    "low": (
        "This alert is rated LOW severity. Investigate when capacity allows. "
        "May be a false positive or low-impact activity."
    ),
    "informational": (
        "This is an INFORMATIONAL alert. No immediate action required. "
        "Review for baseline awareness and threat hunting context."
    ),
}


def _heuristic_analysis(req: AlertAnalysisRequest) -> AlertAnalysis:
    """
    Produce a rule-based analysis when the LLM is unavailable.
    Ensures the service degrades gracefully rather than failing hard.
    """
    severity = req.severity.lower()
    mitre_refs = (
        ", ".join(f"{m.technique_id} ({m.tactic})" for m in req.mitre_matches[:3])
        if req.mitre_matches
        else "no MITRE mapping available"
    )

    summary = (
        f"A {severity}-severity alert '{req.alert_name}' was detected from {req.source} "
        f"on host '{req.host}' (user: '{req.user}'). "
        f"Associated MITRE ATT&CK techniques: {mitre_refs}. "
        f"Automated LLM analysis is currently unavailable; this is a heuristic assessment."
    )

    investigation_steps = [
        f"Verify the alert is genuine by reviewing raw logs for host '{req.host}'.",
        f"Check recent authentication events for user '{req.user}' in the past 24 hours.",
        "Correlate with other alerts from the same source IP or host in the SIEM.",
        "Review process tree and parent-child relationships if endpoint telemetry is available.",
        "Search for indicators of compromise (IOCs) from this alert in threat intel feeds.",
    ]

    recommended_actions: List[str] = []
    if severity in ("critical", "high"):
        recommended_actions += [
            f"Isolate host '{req.host}' from the network pending investigation.",
            f"Reset credentials for user '{req.user}' immediately.",
            "Escalate to Tier-3 / IR team if isolation is confirmed.",
        ]
    else:
        recommended_actions += [
            "Document findings and update alert status in the SIEM.",
            "Monitor the affected host and user for 48 hours.",
        ]
    recommended_actions += [
        "Capture forensic image of affected endpoint if critical.",
        "Update detection rules based on findings to reduce future false positives.",
    ]

    return AlertAnalysis(
        summary=summary,
        risk_assessment=_SEVERITY_RISK.get(severity, _SEVERITY_RISK["medium"]),
        investigation_steps=investigation_steps,
        recommended_actions=recommended_actions,
    )


# ---------------------------------------------------------------------------
# LLM chain builder (lazy import so the module loads even without langchain)
# ---------------------------------------------------------------------------


def _build_chain(
    model: str,
    base_url: str,
    temperature: float,
    timeout: int,
    keep_alive: str,
) -> Any:
    """
    Build and return a LangChain runnable chain:
        ChatOllama | StrOutputParser (raw JSON string)

    We use StrOutputParser here and validate manually via Pydantic so that
    partial / malformed JSON from the LLM is caught and handled gracefully.

    Raises ImportError if langchain-ollama is not installed.
    """
    from langchain_ollama import ChatOllama
    from langchain_core.output_parsers import StrOutputParser

    llm = ChatOllama(
        model=model,
        base_url=base_url,
        temperature=temperature,
        timeout=timeout,
        keep_alive=keep_alive,
        format="json",          # instructs Ollama to constrain output to JSON
    )

    # Simple chain: messages → llm → raw string
    chain = llm | StrOutputParser()
    return chain, SystemMessage(content=_SYSTEM_PROMPT)


# ---------------------------------------------------------------------------
# AlertAnalyzer – public façade
# ---------------------------------------------------------------------------


class AlertAnalyzer:
    """
    LangChain-based alert analysis service backed by a local Ollama model.

    Parameters
    ----------
    model : str
        Ollama model name (default: ``llama3``).
    base_url : str
        Ollama API base URL (default: ``http://localhost:11434``).
    temperature : float
        Sampling temperature – use low values (0.0–0.2) for deterministic output.
    timeout : int
        Per-request timeout in seconds.
    keep_alive : str
        How long Ollama keeps the model loaded between requests.
    max_retries : int
        Number of LLM call retries on transient errors.
    dry_run : bool
        If ``True``, skip the LLM call entirely and return heuristic analysis.
        Useful for tests and environments without Ollama.

    Usage::

        analyzer = AlertAnalyzer()

        result = await analyzer.analyze(
            AlertAnalysisRequest.from_dicts(
                alert=normalized_alert.to_dict(),
                mitre_matches=[m.to_dict() for m in mapping.matches],
            )
        )
        print(result.summary)
        print(result.investigation_steps)
    """

    def __init__(
        self,
        model: str = "llama3",
        base_url: str = "http://localhost:11434",
        temperature: float = 0.1,
        timeout: int = 120,
        keep_alive: str = "5m",
        max_retries: int = 2,
        dry_run: bool = False,
    ) -> None:
        self.model = model
        self.base_url = base_url
        self.temperature = temperature
        self.timeout = timeout
        self.keep_alive = keep_alive
        self.max_retries = max_retries
        self.dry_run = dry_run

        self._chain: Any = None
        self._system_msg: Any = None  # SystemMessage instance

    # ── lifecycle ──────────────────────────────────────────────────────────

    def _ensure_chain(self) -> None:
        """Lazily build the LangChain chain on first use."""
        if self._chain is not None:
            return
        try:
            self._chain, self._system_msg = _build_chain(
                model=self.model,
                base_url=self.base_url,
                temperature=self.temperature,
                timeout=self.timeout,
                keep_alive=self.keep_alive,
            )
            logger.info("llm_analyzer_chain_built: model=%s base_url=%s", self.model, self.base_url)
        except ImportError as exc:
            logger.warning("llm_analyzer_langchain_unavailable: %s", exc)
            # Mark as dry_run so we fall back gracefully
            self.dry_run = True

    # ── public API ─────────────────────────────────────────────────────────

    async def analyze(
        self,
        request: AlertAnalysisRequest,
    ) -> AlertAnalysis:
        """
        Produce a structured analysis for *request*.

        Returns
        -------
        AlertAnalysis
            LLM-generated analysis if Ollama is available, otherwise a
            deterministic heuristic analysis.
        """
        if self.dry_run:
            logger.info("llm_analyzer_dry_run", alert=request.alert_name)
            return _heuristic_analysis(request)

        self._ensure_chain()

        if self.dry_run:  # set by _ensure_chain if import failed
            return _heuristic_analysis(request)

        human_text = _build_human_prompt(request)

        if not _LANGCHAIN_AVAILABLE or HumanMessage is None:
            logger.warning("llm_analyzer_langchain_unavailable: falling back to heuristic")
            return _heuristic_analysis(request)

        messages = [self._system_msg, HumanMessage(content=human_text)]

        for attempt in range(1, self.max_retries + 1):
            t0 = time.perf_counter()
            try:
                raw: str = await self._chain.ainvoke(messages)
                elapsed = time.perf_counter() - t0

                analysis = self._parse_llm_output(raw, request)

                logger.info(
                    "llm_analyzer_success: alert=%s model=%s elapsed=%.2fs attempt=%d",
                    request.alert_name, self.model, elapsed, attempt,
                )
                return analysis

            except Exception as exc:
                logger.warning(
                    "llm_analyzer_attempt_failed: attempt=%d/%d error=%s",
                    attempt, self.max_retries, str(exc)[:200],
                )
                if attempt == self.max_retries:
                    logger.error(
                        "llm_analyzer_falling_back_to_heuristic: alert=%s error=%s",
                        request.alert_name, str(exc)[:200],
                    )
                    return _heuristic_analysis(request)

        # Should not reach here
        return _heuristic_analysis(request)

    def analyze_sync(self, request: AlertAnalysisRequest) -> AlertAnalysis:
        """
        Synchronous wrapper for use outside async contexts (e.g. scripts, CLI).
        """
        import asyncio
        return asyncio.get_event_loop().run_until_complete(self.analyze(request))

    # ── output parsing ────────────────────────────────────────────────────

    def _parse_llm_output(
        self, raw: str, request: AlertAnalysisRequest
    ) -> AlertAnalysis:
        """
        Attempt to parse the LLM's raw string as JSON → AlertAnalysis.

        Falls back to heuristic if:
        - The output is not valid JSON
        - Required fields are missing
        - Values fail Pydantic validation
        """
        raw = raw.strip()

        # Strip markdown code fences if the model wrapped its output
        if raw.startswith("```"):
            lines = raw.splitlines()
            raw = "\n".join(
                ln for ln in lines if not ln.startswith("```")
            ).strip()

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            logger.warning("llm_analyzer_json_parse_failed: %s | preview=%s", exc, raw[:200])
            return _heuristic_analysis(request)

        # Normalise list fields – LLM sometimes returns a single string
        for list_field in ("investigation_steps", "recommended_actions"):
            val = data.get(list_field)
            if isinstance(val, str):
                data[list_field] = [val]
            elif not isinstance(val, list):
                data[list_field] = []

        try:
            return AlertAnalysis(**data)
        except Exception as exc:
            logger.warning("llm_analyzer_validation_failed: %s", str(exc)[:300])
            return _heuristic_analysis(request)


# ---------------------------------------------------------------------------
# Factory helper – reads from app.core.config.settings
# ---------------------------------------------------------------------------


def create_analyzer(dry_run: bool = False) -> AlertAnalyzer:
    """
    Create an ``AlertAnalyzer`` pre-configured from application settings.

    Usage in production (e.g. FastAPI startup)::

        from app.services.llm_analyzer import create_analyzer
        analyzer = create_analyzer()

    In tests::

        analyzer = create_analyzer(dry_run=True)
    """
    try:
        from app.core.config import settings
        return AlertAnalyzer(
            model=settings.OLLAMA_MODEL,
            base_url=settings.OLLAMA_BASE_URL,
            temperature=settings.OLLAMA_TEMPERATURE,
            timeout=settings.OLLAMA_TIMEOUT,
            keep_alive=settings.OLLAMA_KEEP_ALIVE,
            dry_run=dry_run,
        )
    except ImportError:
        # Running outside the full app (e.g. standalone script)
        return AlertAnalyzer(dry_run=dry_run)
