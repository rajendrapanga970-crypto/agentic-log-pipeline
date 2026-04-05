"""
Pre-wired Agent Definitions
  - LogClassificationAgent
  - ThreatDetectionAgent
  - SummaryAgent  (doubles as AlertAgent when severity is high)

Each agent exposes:
  .run(log_event: dict) -> AgentResult
"""

from __future__ import annotations
import re
import json
import logging
import asyncio
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)


# ─── Shared result type ───────────────────────────────────────────────────────
@dataclass
class AgentResult:
    agent: str
    classification: Optional[str] = None
    analysis: Optional[str] = None
    summary: Optional[str] = None
    severity: Optional[int] = None
    recommended_action: Optional[str] = None
    similar_events: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v is not None and v != []}


# ─── Keyword rules (deterministic layer — no LLM needed) ─────────────────────
MALICIOUS_KW = [
    "injection", "brute force", "port scan", "exploit", "payload",
    "malware", "ransomware", "reverse shell", "exfiltration", "backdoor",
    "unauthorized access", "privilege escalation", "zero-day",
]
DENY_KW = [
    "timeout", "connection refused", "failed", "error", "denied",
    "rejected", "unreachable", "exception", "traceback", "crash",
]

def _rule_classify(level: str, message: str) -> tuple[str, int]:
    """Returns (classification, severity 1-10)."""
    msg = message.lower()
    lvl = (level or "INFO").upper()

    if any(k in msg for k in MALICIOUS_KW) or lvl == "CRITICAL":
        return "malicious", 9
    if any(k in msg for k in DENY_KW) or lvl == "ERROR":
        return "deny", 6
    if lvl == "WARN":
        return "deny", 3
    return "allowed", 1


# ─── Base agent (shared LLM call) ────────────────────────────────────────────
class BaseAgent:
    def __init__(self, ollama_url: str = "http://ollama:11434", model: str = "mistral"):
        self.ollama_url = ollama_url
        self.model = model

    async def _llm(self, prompt: str) -> str:
        try:
            import httpx
            async with httpx.AsyncClient(timeout=60) as client:
                r = await client.post(
                    f"{self.ollama_url}/api/generate",
                    json={"model": self.model, "prompt": prompt, "stream": False},
                )
                r.raise_for_status()
                return r.json().get("response", "").strip()
        except Exception as e:
            log.warning(f"[{self.__class__.__name__}] LLM unavailable: {e}")
            return f"[LLM offline] {prompt[:60]}…"


# ─── Agent 1: Log Classification Agent ───────────────────────────────────────
class LogClassificationAgent(BaseAgent):
    """
    Classifies every log event as allowed / deny / malicious.
    Uses deterministic keyword rules first; LLM for explanation.
    """
    NAME = "log_classification"

    async def run(self, log_event: dict) -> AgentResult:
        level   = log_event.get("level", "INFO")
        message = log_event.get("message", "")
        source  = log_event.get("source", "unknown")

        classification, severity = _rule_classify(level, message)

        prompt = (
            f"You are a security log classifier. A log arrived:\n"
            f"  Level:   {level}\n"
            f"  Source:  {source}\n"
            f"  Message: {message}\n\n"
            f"Rule-based classification: {classification} (severity {severity}/10)\n"
            f"In ONE sentence, confirm or correct this and explain why."
        )
        explanation = await self._llm(prompt)

        return AgentResult(
            agent=self.NAME,
            classification=classification,
            severity=severity,
            analysis=explanation,
            metadata={"level": level, "source": source},
        )


# ─── Agent 2: Threat Detection Agent ─────────────────────────────────────────
class ThreatDetectionAgent(BaseAgent):
    """
    Deep analysis for malicious / critical logs.
    Performs RAG lookup for similar past threats.
    """
    NAME = "threat_detection"

    def __init__(self, qdrant_client=None, embed_fn=None, **kwargs):
        super().__init__(**kwargs)
        self.qdrant = qdrant_client
        self.embed  = embed_fn

    async def run(self, log_event: dict) -> AgentResult:
        level   = log_event.get("level", "INFO")
        message = log_event.get("message", "")
        source  = log_event.get("source", "unknown")

        prompt = (
            f"You are a senior cybersecurity analyst. Analyze this security event:\n"
            f"  Level:   {level}\n"
            f"  Source:  {source}\n"
            f"  Message: {message}\n\n"
            f"Return a structured analysis with:\n"
            f"  threat_type: (e.g. SQL Injection, Brute Force, Port Scan…)\n"
            f"  attack_vector: (network / application / insider / unknown)\n"
            f"  severity: (1-10)\n"
            f"  recommended_action: (immediate steps to take)\n"
            f"Be specific and concise."
        )
        analysis = await self._llm(prompt)

        # RAG: similar past threats from Qdrant
        similar = []
        if self.qdrant and self.embed:
            try:
                from qdrant_client.models import Filter, FieldCondition, MatchValue
                vec  = self.embed(f"[{level}] {source}: {message}")
                hits = self.qdrant.search(
                    collection_name="logs_collection",
                    query_vector=vec,
                    query_filter=Filter(must=[
                        FieldCondition(key="classification", match=MatchValue(value="malicious"))
                    ]),
                    limit=3,
                )
                similar = [h.payload.get("message", "") for h in hits if h.score > 0.5]
            except Exception as e:
                log.warning(f"ThreatAgent RAG lookup failed: {e}")

        # Parse severity from LLM response
        sev_match = re.search(r"severity[:\s]+(\d+)", analysis, re.IGNORECASE)
        severity  = int(sev_match.group(1)) if sev_match else 8

        return AgentResult(
            agent=self.NAME,
            classification="malicious",
            severity=severity,
            analysis=analysis,
            recommended_action="Isolate affected system and escalate to security team.",
            similar_events=similar,
            metadata={"level": level, "source": source},
        )


# ─── Agent 3: Summary Agent (also handles Alert path) ────────────────────────
class SummaryAgent(BaseAgent):
    """
    For allowed logs: concise human-readable summary.
    For deny/error logs: root-cause hypothesis + remediation steps.
    """
    NAME = "summary"

    async def run(self, log_event: dict) -> AgentResult:
        level   = log_event.get("level", "INFO")
        message = log_event.get("message", "")
        source  = log_event.get("source", "unknown")
        cls, severity = _rule_classify(level, message)

        if cls == "deny":
            prompt = (
                f"You are an operations engineer. This log indicates a problem:\n"
                f"  [{level}] {source}: {message}\n\n"
                f"Provide:\n"
                f"  root_cause: (most likely reason)\n"
                f"  impact: (what is affected)\n"
                f"  action: (immediate remediation step)\n"
                f"Keep each to one sentence."
            )
            agent_name = "alert"
        else:
            prompt = (
                f"Summarize this log event in one clear sentence for an ops dashboard:\n"
                f"  [{level}] {source}: {message}"
            )
            agent_name = "summary"

        response = await self._llm(prompt)

        return AgentResult(
            agent=agent_name,
            classification=cls,
            severity=severity,
            summary=response,
            metadata={"level": level, "source": source},
        )


# ─── Agent factory ────────────────────────────────────────────────────────────
def create_agents(ollama_url: str = "http://ollama:11434",
                  qdrant_client=None,
                  embed_fn=None) -> dict:
    """Return all agents keyed by name."""
    return {
        "classify": LogClassificationAgent(ollama_url=ollama_url),
        "threat":   ThreatDetectionAgent(ollama_url=ollama_url,
                                         qdrant_client=qdrant_client,
                                         embed_fn=embed_fn),
        "summary":  SummaryAgent(ollama_url=ollama_url),
    }
