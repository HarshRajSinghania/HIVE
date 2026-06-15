#!/usr/bin/env python3
"""
hive_ai.py  —  HIVE Platform · Stage 5: AI Investigative Intelligence Engine
═══════════════════════════════════════════════════════════════════════════════
High-scale Investigation and Verification Engine  (HIVE)  v1.0.0

Evidence-aware AI analysis layer powered by NVIDIA NIM and Nemotron Super.
Retrieves curated evidence from MongoDB, builds structured investigative
context, and invokes Nemotron Super to produce traceable, evidence-bound
analytical assessments.

Architecture (Retrieval-Augmented Analysis)
  1. Query Planner     — classifies investigator intent, identifies targets
  2. Context Retriever — fetches relevant evidence from MongoDB (never raw DB)
  3. Prompt Builder    — formats evidence context for Nemotron Super
  4. NIM Client        — streams inference via NVIDIA NIM API
  5. Analysis Engine   — parses structured AI response, validates evidence links
  6. Audit Store       — persists every analysis to MongoDB with full provenance

Supported workflows
  Entity analysis · Device analysis · Cluster analysis · Infrastructure mapping
  Timeline reconstruction · Relationship explanation · Risk assessment
  Target prioritisation · Hypothesis generation · Intelligence report generation
  Actor attribution · Anomaly detection · Behavioral analysis

Design principles
  • AI is an analytical assistant — never a legal source of truth
  • Every finding must cite specific evidence present in the context
  • Confidence scores required on every assessment
  • Full audit trail in MongoDB (model, temperature, context hash, timestamp)
  • Streaming output — investigators see reasoning as it unfolds

MongoDB collections (written by this module)
  ai_analyses      — every AI-generated analysis with provenance
  ai_sessions      — investigator session records
  ai_hypotheses    — extracted hypotheses for downstream tracking
  ai_recommendations — actionable recommendations for case management

Required
  pip install requests pymongo

Optional (preferred for streaming)
  pip install openai    (OpenAI-compatible client for NVIDIA NIM)

Environment variables
  NVIDIA_API_KEY    — NVIDIA NIM API key (required)
  HIVE_AI_MODEL     — override default model
  HIVE_MONGO_URI    — override MongoDB URI

Pipeline position
  collector → parser → correlator → investigator → [hive_ai.py]

Usage:
  python3 hive_ai.py --case-id CASE-001                          # interactive
  python3 hive_ai.py --case-id CASE-001 --ask "Who are the operators?"
  python3 hive_ai.py --case-id CASE-001 --analyze cluster CLUSTER-A1B2
  python3 hive_ai.py --case-id CASE-001 --brief --output brief.md
  python3 hive_ai.py --case-id CASE-001 --batch queries.txt
═══════════════════════════════════════════════════════════════════════════════
"""

from __future__ import annotations

import os
import re
import sys
import cmd
import json
import uuid
import time
import hashlib
import logging
import argparse
import datetime
import textwrap
import readline
import threading
import collections
from dataclasses import dataclass, field, asdict
from typing      import Optional, List, Dict, Any, Iterator, Tuple

# ── Optional: requests (preferred for NIM) ────────────────────────────────────
try:
    import requests as _requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ── Optional: openai (OpenAI-compatible client for NIM) ───────────────────────
try:
    from openai import OpenAI as _OpenAIClient
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False

# ── Optional: pymongo ─────────────────────────────────────────────────────────
try:
    import pymongo
    import pymongo.errors
    HAS_MONGO = True
except ImportError:
    HAS_MONGO = False

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

HIVE_AI_VERSION  = "1.0.0"
HIVE_TOOL        = "HIVE-AI"
DATE_FMT         = "%Y-%m-%dT%H:%M:%SZ"
LOG_FMT          = "[%(asctime)s] %(levelname)-8s %(name)s — %(message)s"

# NVIDIA NIM defaults
NIM_BASE_URL     = "https://integrate.api.nvidia.com/v1"
NIM_DEFAULT_MODEL= os.environ.get(
    "HIVE_AI_MODEL", "nvidia/llama-3.3-nemotron-super-49b-v1")
NIM_TEMPERATURE  = 0.20    # low temperature for analytical consistency
NIM_MAX_TOKENS   = 4096    # maximum response tokens
NIM_TIMEOUT_S    = 120     # request timeout

# MongoDB defaults
DEFAULT_MONGO_URI= os.environ.get("HIVE_MONGO_URI", "mongodb://localhost:27017")
DEFAULT_MONGO_DB = "hive"

# Context budget (tokens ≈ chars / 4)
MAX_CONTEXT_CHARS= 80_000   # ~20k tokens of retrieved evidence context
MAX_HISTORY_TURNS= 6        # conversation turns kept in memory

HISTORY_FILE     = os.path.expanduser("~/.hive_ai_history")

# ─────────────────────────────────────────────────────────────────────────────
# ANSI Console
# ─────────────────────────────────────────────────────────────────────────────

class C:
    _ON  = sys.stdout.isatty()
    _MAP = {
        "R":"\033[91m","G":"\033[92m","Y":"\033[93m","B":"\033[94m",
        "M":"\033[95m","C":"\033[96m","W":"\033[97m",
        "BD":"\033[1m","DM":"\033[2m","IT":"\033[3m","RS":"\033[0m",
    }
    @classmethod
    def _c(cls, t, *k):
        return ("".join(cls._MAP.get(x,"") for x in k)+t+cls._MAP["RS"]) \
            if cls._ON else t
    @classmethod
    def red(cls,t):    return cls._c(t,"R")
    @classmethod
    def green(cls,t):  return cls._c(t,"G")
    @classmethod
    def yellow(cls,t): return cls._c(t,"Y")
    @classmethod
    def cyan(cls,t):   return cls._c(t,"C")
    @classmethod
    def magenta(cls,t):return cls._c(t,"M")
    @classmethod
    def bold(cls,t):   return cls._c(t,"BD")
    @classmethod
    def dim(cls,t):    return cls._c(t,"DM")
    @classmethod
    def risk(cls, level: str) -> str:
        return {"CRITICAL": cls._c(level,"R","BD"),
                "HIGH":     cls._c(level,"R"),
                "MEDIUM":   cls._c(level,"Y"),
                "LOW":      cls._c(level,"G")}.get(level, level)
    @classmethod
    def off(cls): cls._ON = False


AI_BANNER = """
  ╔═══════════════════════════════════════════════════════╗
  ║  HIVE-AI  ·  Investigative Intelligence Engine  v{v}  ║
  ║  Powered by NVIDIA NIM  ·  Nemotron Super             ║
  ╚═══════════════════════════════════════════════════════╝"""

AI_HELP = """
┌──────────────────────────────────────────────────────────────┐
│  HIVE-AI Command Reference                                    │
├──────────────────────────────────────────────────────────────┤
│  NATURAL LANGUAGE QUERIES                                     │
│    ask <question>         Free-form investigative query       │
│    follow <question>      Follow-up on the last analysis      │
│                                                               │
│  TARGETED ANALYSIS                                            │
│    analyze device  <id>   Full AI device assessment           │
│    analyze cluster <id>   AI cluster characterisation         │
│    analyze entity  <val>  Entity significance assessment      │
│    analyze rel <a> <b>    Explain the link between devices    │
│                                                               │
│  CASE-LEVEL INTELLIGENCE                                      │
│    brief                  Generate case intelligence brief    │
│    risks                  Risk assessment for all devices     │
│    prioritize             AI-ranked investigation targets     │
│    hypotheses             Generate investigative hypotheses   │
│    timeline [device]      AI timeline reconstruction          │
│    actors                 Probable operator attribution       │
│    infrastructure         Criminal infrastructure mapping     │
│                                                               │
│  SESSION & AUDIT                                              │
│    history [n]            Show last N AI analyses             │
│    export [file]          Export session to Markdown          │
│    stats                  AI usage statistics                 │
│                                                               │
│    help  |  exit                                              │
└──────────────────────────────────────────────────────────────┘"""

# ─────────────────────────────────────────────────────────────────────────────
# System Prompt  (Nemotron Super persona + output contract)
# ─────────────────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """\
You are HIVE-AI, an advanced digital forensics and criminal intelligence \
analysis assistant operating as part of the HIVE (High-scale Investigation \
and Verification Engine) platform. You assist authorised law enforcement \
officers, DFIR analysts, and intelligence professionals in understanding \
complex forensic evidence gathered from seized digital devices.

═══ CORE PRINCIPLES ═══════════════════════════════════════════════════
1. EVIDENCE-BOUND REASONING
   Every conclusion must be directly supported by evidence provided in the
   context block. Never fabricate facts, invent entity values, or reference
   devices, relationships, or events not present in the supplied data.

2. CONFIDENCE SCORING
   All assessments must include numeric confidence scores (0.0–1.0).
   Base confidence on: evidence volume, entity uniqueness, consistency,
   and corroboration across multiple sources.

3. FULL TRACEABILITY
   Every key finding must cite the specific device IDs, entity values,
   relationship IDs, or timeline events from the context that support it.

4. INVESTIGATIVE NEUTRALITY
   Present findings objectively. Where evidence is ambiguous, explicitly
   acknowledge alternative interpretations. Never overstate certainty.

5. LEGAL AWARENESS
   Your outputs are analytical tools only — not legal conclusions.
   Always recommend investigators corroborate critical findings through
   additional forensic work or intelligence.

6. DATA GAPS
   If the provided context is insufficient to answer the query, state
   the specific gaps explicitly rather than speculating.

═══ MANDATORY OUTPUT FORMAT ════════════════════════════════════════════
Always respond with a single valid JSON object matching this schema exactly:

{
  "analysis_type": "<string: type of analysis performed>",
  "summary": "<string: 2-4 sentence executive summary>",
  "key_findings": [
    {
      "finding": "<string: specific finding>",
      "confidence": <float 0.0-1.0>,
      "evidence": ["<specific entity/device/event from context>", ...]
    }
  ],
  "hypotheses": [
    {
      "hypothesis": "<string: investigative hypothesis>",
      "confidence": <float 0.0-1.0>,
      "supporting_evidence": ["<from context>"],
      "contradicting_evidence": ["<from context or absence>"]
    }
  ],
  "risk_assessment": {
    "level": "<CRITICAL|HIGH|MEDIUM|LOW>",
    "rationale": "<string>",
    "confidence": <float 0.0-1.0>
  },
  "key_entities": [
    {
      "type": "<entity type>",
      "value": "<entity value from context>",
      "significance": "<why this entity matters>",
      "devices": ["<device IDs>"]
    }
  ],
  "recommended_actions": [
    {
      "action": "<specific investigative action>",
      "priority": "<HIGH|MEDIUM|LOW>",
      "rationale": "<why this action is valuable>"
    }
  ],
  "investigative_questions": ["<unanswered questions raised by the evidence>"],
  "analyst_notes": "<string: caveats, data limitations, assumptions>"
}

Respond ONLY with the JSON object — no markdown fences, no preamble, no postamble."""

# ─────────────────────────────────────────────────────────────────────────────
# Data Models
# ─────────────────────────────────────────────────────────────────────────────

class AnalysisIntent:
    ENTITY_ANALYSIS      = "ENTITY_ANALYSIS"
    DEVICE_ANALYSIS      = "DEVICE_ANALYSIS"
    CLUSTER_ANALYSIS     = "CLUSTER_ANALYSIS"
    RELATIONSHIP_EXPLAIN = "RELATIONSHIP_EXPLANATION"
    TIMELINE_RECONSTRUCT = "TIMELINE_RECONSTRUCTION"
    RISK_ASSESSMENT      = "RISK_ASSESSMENT"
    TARGET_PRIORITY      = "TARGET_PRIORITIZATION"
    INFRASTRUCTURE_MAP   = "INFRASTRUCTURE_MAPPING"
    HYPOTHESIS_GEN       = "HYPOTHESIS_GENERATION"
    ACTOR_ATTRIBUTION    = "ACTOR_ATTRIBUTION"
    REPORT_GENERATION    = "REPORT_GENERATION"
    ANOMALY_DETECTION    = "ANOMALY_DETECTION"
    GENERAL_QUERY        = "GENERAL_QUERY"


@dataclass
class QueryPlan:
    """Structured plan produced by the Query Planner for one investigator query."""
    query:         str
    intent:        str  = AnalysisIntent.GENERAL_QUERY
    target_entity: str  = ""
    target_device: str  = ""
    target_cluster:str  = ""
    device_pair:   Tuple[str,str] = ("","")
    requires_timeline: bool = False
    requires_clusters: bool = False
    requires_entities: bool = True
    requires_relationships: bool = True
    requires_leads:    bool = True
    context_hint:  str  = ""


@dataclass
class InvestigativeContext:
    """Curated evidence block retrieved for one analysis."""
    case_id:       str            = ""
    query:         str            = ""
    intent:        str            = ""
    case_overview: Dict           = field(default_factory=dict)
    devices:       List[Dict]     = field(default_factory=list)
    target_device: Dict           = field(default_factory=dict)
    target_cluster:Dict           = field(default_factory=dict)
    relationships: List[Dict]     = field(default_factory=list)
    clusters:      List[Dict]     = field(default_factory=list)
    leads:         List[Dict]     = field(default_factory=list)
    entities:      List[Dict]     = field(default_factory=list)
    timeline:      List[Dict]     = field(default_factory=list)
    infra_links:   List[Dict]     = field(default_factory=list)
    custom:        Dict           = field(default_factory=dict)
    retrieved_at:  str            = field(default_factory=lambda: _utcnow())
    context_hash:  str            = ""


@dataclass
class AIAnalysis:
    """One AI-generated analysis with full provenance."""
    analysis_id:     str   = field(default_factory=lambda: str(uuid.uuid4()))
    session_id:      str   = ""
    case_id:         str   = ""
    query:           str   = ""
    intent:          str   = ""
    model:           str   = NIM_DEFAULT_MODEL
    temperature:     float = NIM_TEMPERATURE
    context_hash:    str   = ""
    prompt_tokens:   int   = 0
    completion_tokens:int  = 0

    # Parsed AI output
    analysis_type:   str   = ""
    summary:         str   = ""
    key_findings:    List  = field(default_factory=list)
    hypotheses:      List  = field(default_factory=list)
    risk_assessment: Dict  = field(default_factory=dict)
    key_entities:    List  = field(default_factory=list)
    recommended_actions: List = field(default_factory=list)
    investigative_questions: List = field(default_factory=list)
    analyst_notes:   str   = ""

    raw_response:    str   = ""
    parse_error:     str   = ""
    duration_s:      float = 0.0
    created_at:      str   = field(default_factory=lambda: _utcnow())
    investigator:    str   = ""


@dataclass
class AISession:
    """A single investigator session with conversation history."""
    session_id:   str   = field(default_factory=lambda: str(uuid.uuid4()))
    case_id:      str   = ""
    investigator: str   = ""
    model:        str   = NIM_DEFAULT_MODEL
    started_at:   str   = field(default_factory=lambda: _utcnow())
    ended_at:     str   = ""
    analysis_ids: List  = field(default_factory=list)
    turn_count:   int   = 0
    # In-memory conversation turns: [{"role": "user"|"assistant", "content": str}]
    history:      List  = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# Utilities
# ─────────────────────────────────────────────────────────────────────────────

def _utcnow() -> str:
    return datetime.datetime.utcnow().strftime(DATE_FMT)


def _trunc(s: str, n: int) -> str:
    s = str(s)
    return s[:n - 1] + "…" if len(s) > n else s


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def _estimate_tokens(text: str) -> int:
    return len(text) // 4


def _setup_logging(verbose: bool = False) -> logging.Logger:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(level=level, format=LOG_FMT)
    return logging.getLogger("hive.ai")


# ─────────────────────────────────────────────────────────────────────────────
# NVIDIA NIM Client
# ─────────────────────────────────────────────────────────────────────────────

class NIMClient:
    """
    HTTP client for NVIDIA NIM inference API (OpenAI-compatible).

    Supports both blocking and streaming (SSE) completion.
    Uses `requests` by default; falls back to `openai` library if available.
    """

    def __init__(self, api_key: str, model: str = NIM_DEFAULT_MODEL,
                  base_url: str = NIM_BASE_URL):
        self.api_key  = api_key
        self.model    = model
        self.base_url = base_url.rstrip("/")
        self.log      = logging.getLogger("hive.ai.nim")

        if not HAS_REQUESTS and not HAS_OPENAI:
            raise ImportError(
                "Install requests or openai:  pip install requests  OR  pip install openai")

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type":  "application/json",
            "Accept":        "application/json",
        }

    def complete(self, messages: List[Dict],
                  temperature: float = NIM_TEMPERATURE,
                  max_tokens:  int   = NIM_MAX_TOKENS) -> Tuple[str, int, int]:
        """
        Blocking completion.  Returns (content, prompt_tokens, completion_tokens).
        """
        payload = {
            "model":       self.model,
            "messages":    messages,
            "temperature": temperature,
            "max_tokens":  max_tokens,
        }
        t0 = time.time()

        if HAS_OPENAI:
            return self._complete_openai(payload)

        if not HAS_REQUESTS:
            raise RuntimeError("requests library not available")

        resp = _requests.post(
            f"{self.base_url}/chat/completions",
            headers=self._headers(),
            json=payload,
            timeout=NIM_TIMEOUT_S,
        )
        resp.raise_for_status()
        data  = resp.json()
        msg   = data["choices"][0]["message"]["content"]
        usage = data.get("usage", {})
        self.log.debug(f"NIM complete: {time.time()-t0:.1f}s  "
                        f"tokens={usage.get('total_tokens',0)}")
        return msg, usage.get("prompt_tokens",0), usage.get("completion_tokens",0)

    def _complete_openai(self, payload: Dict) -> Tuple[str, int, int]:
        client = _OpenAIClient(base_url=self.base_url, api_key=self.api_key)
        resp   = client.chat.completions.create(**payload)
        msg    = resp.choices[0].message.content
        usage  = resp.usage
        return msg, usage.prompt_tokens, usage.completion_tokens

    def stream(self, messages: List[Dict],
                temperature: float = NIM_TEMPERATURE,
                max_tokens:  int   = NIM_MAX_TOKENS) -> Iterator[str]:
        """
        Streaming completion via Server-Sent Events.
        Yields text chunks as they arrive.
        """
        payload = {
            "model":       self.model,
            "messages":    messages,
            "temperature": temperature,
            "max_tokens":  max_tokens,
            "stream":      True,
        }

        if HAS_OPENAI:
            yield from self._stream_openai(payload)
            return

        if not HAS_REQUESTS:
            # Fallback: blocking call, yield full response at once
            content, _, _ = self.complete(messages, temperature, max_tokens)
            yield content
            return

        headers = {**self._headers(), "Accept": "text/event-stream"}
        with _requests.post(
            f"{self.base_url}/chat/completions",
            headers=headers, json=payload,
            timeout=NIM_TIMEOUT_S, stream=True,
        ) as resp:
            resp.raise_for_status()
            for raw_line in resp.iter_lines():
                if not raw_line:
                    continue
                line = raw_line.decode("utf-8") if isinstance(raw_line, bytes) \
                    else raw_line
                if not line.startswith("data: "):
                    continue
                data_str = line[6:].strip()
                if data_str == "[DONE]":
                    break
                try:
                    chunk = json.loads(data_str)
                    delta = chunk["choices"][0]["delta"].get("content", "")
                    if delta:
                        yield delta
                except (json.JSONDecodeError, KeyError, IndexError):
                    pass

    def _stream_openai(self, payload: Dict) -> Iterator[str]:
        client = _OpenAIClient(base_url=self.base_url, api_key=self.api_key)
        with client.chat.completions.create(**payload) as stream:
            for chunk in stream:
                delta = chunk.choices[0].delta.content
                if delta:
                    yield delta

    def health_check(self) -> bool:
        """Verify the NIM endpoint is reachable."""
        try:
            resp = _requests.get(
                f"{self.base_url}/models",
                headers=self._headers(), timeout=10)
            return resp.status_code == 200
        except Exception:
            return False


# ─────────────────────────────────────────────────────────────────────────────
# Query Planner
# ─────────────────────────────────────────────────────────────────────────────

class QueryPlanner:
    """
    Classifies investigator intent and identifies evidence targets from a
    natural language query.  Uses keyword heuristics + entity detection
    to avoid spending inference budget on intent classification.
    """

    # (pattern, intent) pairs, checked in order
    _INTENT_PATTERNS: List[Tuple[str, str]] = [
        (r"timeline|sequence|chronolog|order of events|what happened|"
         r"reconstruct|narrative|when did",        AnalysisIntent.TIMELINE_RECONSTRUCT),
        (r"cluster|group|network|gang|ring|"
         r"operation|cartel|syndicate",             AnalysisIntent.CLUSTER_ANALYSIS),
        (r"why.*link|why.*connect|explain.*link|"
         r"explain.*connect|relationship.*between|"
         r"what.*link|how.*related",               AnalysisIntent.RELATIONSHIP_EXPLAIN),
        (r"risk|threat|danger|critical|severity|"
         r"how serious|how dangerous",              AnalysisIntent.RISK_ASSESSMENT),
        (r"prioriti|most important|focus on|"
         r"investigate first|which device",         AnalysisIntent.TARGET_PRIORITY),
        (r"infrastructure|c2|command.and.control|"
         r"server|hosting|botnet|phishing",         AnalysisIntent.INFRASTRUCTURE_MAP),
        (r"who.*operator|who.*behind|actor|person|"
         r"individual|suspect|attacker|perpetrat",  AnalysisIntent.ACTOR_ATTRIBUTION),
        (r"report|brief|summary|intelligence|"
         r"summarize|overview|digest",              AnalysisIntent.REPORT_GENERATION),
        (r"hypothesis|theory|could be|might be|"
         r"possible|speculate|scenario",            AnalysisIntent.HYPOTHESIS_GEN),
        (r"anomal|unusual|strange|suspicious|"
         r"outlier|unexpected",                     AnalysisIntent.ANOMALY_DETECTION),
        (r"wallet|bitcoin|btc|ethereum|eth|"
         r"crypto|coin|blockchain",                 AnalysisIntent.ENTITY_ANALYSIS),
        (r"email|phone|ip address|domain|url|"
         r"hash|imei|mac address|username",         AnalysisIntent.ENTITY_ANALYSIS),
        (r"device|handset|laptop|computer|"
         r"android|windows|linux|phone",            AnalysisIntent.DEVICE_ANALYSIS),
    ]

    # Patterns for extracting structured targets from the query
    _CLUSTER_RE = re.compile(r"\bCLUSTER[-_][A-Z0-9]+\b", re.I)
    _DEVICE_RE  = re.compile(
        r"\b(?:android|windows|linux|ios|macos|disk|lnx|win)_\S+\b", re.I)
    _IP_RE      = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
    _EMAIL_RE   = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
    _BTC_RE     = re.compile(r"(?:1|3)[a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{11,71}")
    _ETH_RE     = re.compile(r"0x[a-fA-F0-9]{40}")
    _PHONE_RE   = re.compile(r"\+?[1-9]\d{6,14}")

    def plan(self, query: str) -> QueryPlan:
        q   = query.lower()
        plan= QueryPlan(query=query)

        # Classify intent
        for pattern, intent in self._INTENT_PATTERNS:
            if re.search(pattern, q):
                plan.intent = intent
                break

        # Extract structured targets
        cm = self._CLUSTER_RE.search(query)
        if cm:
            plan.target_cluster = cm.group(0).upper()
            if plan.intent == AnalysisIntent.GENERAL_QUERY:
                plan.intent = AnalysisIntent.CLUSTER_ANALYSIS

        dm = self._DEVICE_RE.findall(query)
        if dm:
            plan.target_device = dm[0]
            if len(dm) >= 2:
                plan.device_pair = (dm[0], dm[1])
                if plan.intent == AnalysisIntent.GENERAL_QUERY:
                    plan.intent = AnalysisIntent.RELATIONSHIP_EXPLAIN
            elif plan.intent == AnalysisIntent.GENERAL_QUERY:
                plan.intent = AnalysisIntent.DEVICE_ANALYSIS

        for rx in (self._BTC_RE, self._ETH_RE, self._EMAIL_RE,
                    self._IP_RE, self._PHONE_RE):
            m = rx.search(query)
            if m:
                plan.target_entity = m.group(0)
                if plan.intent == AnalysisIntent.GENERAL_QUERY:
                    plan.intent = AnalysisIntent.ENTITY_ANALYSIS
                break

        # Set context requirements by intent
        plan.requires_timeline = plan.intent in (
            AnalysisIntent.TIMELINE_RECONSTRUCT,
            AnalysisIntent.ACTOR_ATTRIBUTION,
            AnalysisIntent.ANOMALY_DETECTION,
        )
        plan.requires_clusters = plan.intent in (
            AnalysisIntent.CLUSTER_ANALYSIS,
            AnalysisIntent.INFRASTRUCTURE_MAP,
            AnalysisIntent.ACTOR_ATTRIBUTION,
            AnalysisIntent.REPORT_GENERATION,
        )
        plan.context_hint = (
            f"Intent={plan.intent}  "
            f"Target={'cluster='+plan.target_cluster if plan.target_cluster else ''}"
            f"{'device='+plan.target_device if plan.target_device else ''}"
            f"{'entity='+plan.target_entity if plan.target_entity else ''}"
        )
        return plan


# ─────────────────────────────────────────────────────────────────────────────
# Context Retriever
# ─────────────────────────────────────────────────────────────────────────────

class ContextRetriever:
    """
    Fetches a curated, token-budgeted evidence block from MongoDB.

    Never dumps entire collections — retrieves only what is relevant to
    the query plan so the AI can reason tightly over current evidence.
    """

    def __init__(self, db, case_id: str):   # db = pymongo database
        self.db      = db
        self.case_id = case_id
        self.log     = logging.getLogger("hive.ai.context")

    def _c(self, name: str):
        return self.db[name]

    def retrieve(self, plan: QueryPlan) -> InvestigativeContext:
        ctx = InvestigativeContext(case_id=self.case_id,
                                    query=plan.query, intent=plan.intent)
        # ── Always included ────────────────────────────────────
        ctx.case_overview  = self._case_overview()
        ctx.devices        = self._devices()

        # ── Intent-specific ────────────────────────────────────
        if plan.intent == AnalysisIntent.CLUSTER_ANALYSIS or plan.requires_clusters:
            ctx.clusters = self._clusters()
            if plan.target_cluster:
                ctx.target_cluster = self._cluster(plan.target_cluster)

        if plan.intent in (AnalysisIntent.DEVICE_ANALYSIS,
                            AnalysisIntent.RELATIONSHIP_EXPLAIN):
            if plan.target_device:
                ctx.target_device = self._device_detail(plan.target_device)
            if plan.device_pair[0] and plan.device_pair[1]:
                ctx.custom["device_pair_a"] = self._device_detail(plan.device_pair[0])
                ctx.custom["device_pair_b"] = self._device_detail(plan.device_pair[1])
                ctx.custom["relationship"]  = self._relationship_between(
                    plan.device_pair[0], plan.device_pair[1])

        if plan.intent in (AnalysisIntent.ENTITY_ANALYSIS, ) or plan.target_entity:
            ctx.entities   = self._entity_network(plan.target_entity)
            ctx.infra_links= self._infra_links(plan.target_entity)

        if plan.intent == AnalysisIntent.INFRASTRUCTURE_MAP:
            ctx.infra_links = self._all_infra_links()
            ctx.entities    = self._top_entities()

        if plan.requires_timeline or plan.intent == AnalysisIntent.TIMELINE_RECONSTRUCT:
            ctx.timeline = self._timeline(plan.target_device or None)

        if plan.intent in (AnalysisIntent.ACTOR_ATTRIBUTION,
                            AnalysisIntent.RISK_ASSESSMENT,
                            AnalysisIntent.TARGET_PRIORITY,
                            AnalysisIntent.REPORT_GENERATION,
                            AnalysisIntent.ANOMALY_DETECTION,
                            AnalysisIntent.GENERAL_QUERY):
            ctx.clusters      = ctx.clusters or self._clusters()
            ctx.relationships = self._top_relationships()
            ctx.entities      = ctx.entities or self._top_entities()

        ctx.leads         = self._leads()
        ctx.relationships = ctx.relationships or self._top_relationships(n=20)

        # Compute context hash for audit
        ctx.context_hash = _hash(json.dumps(asdict(ctx), default=str))
        return ctx

    def _case_overview(self) -> Dict:
        run = self._c("correlation_runs").find_one(
            {"case_id": self.case_id}, {"_id": 0},
            sort=[("completed_at", -1)])
        return run or {"case_id": self.case_id}

    def _devices(self) -> List[Dict]:
        return list(self._c("devices").find(
            {"case_id": self.case_id}, {"_id": 0, "manifest_json": 0}))

    def _clusters(self) -> List[Dict]:
        return list(self._c("device_clusters").find(
            {"case_id": self.case_id}, {"_id": 0}).sort("device_count", -1).limit(20))

    def _cluster(self, cluster_id: str) -> Dict:
        return self._c("device_clusters").find_one(
            {"cluster_id": cluster_id}, {"_id": 0}) or {}

    def _device_detail(self, device_id: str) -> Dict:
        dev   = self._c("devices").find_one(
            {"case_id": self.case_id, "device_id": device_id},
            {"_id": 0, "manifest_json": 0}) or {}
        rels  = list(self._c("device_relationships").find(
            {"case_id": self.case_id,
             "$or": [{"device_a": device_id}, {"device_b": device_id}]},
            {"_id": 0}).sort("confidence_score", -1).limit(10))
        ents  = list(self._c("entity_network").find(
            {"case_id": self.case_id, "devices": device_id,
             "device_count": {"$gte": 2}},
            {"_id": 0}).sort("significance", -1).limit(15))
        leads = list(self._c("investigative_leads").find(
            {"case_id": self.case_id, "devices": device_id},
            {"_id": 0}).sort("confidence", -1).limit(5))
        return {**dev, "relationships": rels,
                 "shared_entities": ents, "leads": leads}

    def _relationship_between(self, dev_a: str, dev_b: str) -> Dict:
        rel = self._c("device_relationships").find_one(
            {"case_id": self.case_id,
             "$or": [{"device_a": dev_a, "device_b": dev_b},
                     {"device_a": dev_b, "device_b": dev_a}]},
            {"_id": 0})
        return rel or {}

    def _entity_network(self, value: str) -> List[Dict]:
        filt = {"case_id": self.case_id}
        if value:
            filt["entity_value"] = {"$regex": re.escape(value), "$options": "i"}
        return list(self._c("entity_network").find(
            filt, {"_id": 0}).sort("significance", -1).limit(20))

    def _top_entities(self) -> List[Dict]:
        return list(self._c("entity_network").find(
            {"case_id": self.case_id, "device_count": {"$gte": 2}},
            {"_id": 0}).sort("significance", -1).limit(25))

    def _top_relationships(self, n: int = 15) -> List[Dict]:
        return list(self._c("device_relationships").find(
            {"case_id": self.case_id}, {"_id": 0}
        ).sort("confidence_score", -1).limit(n))

    def _leads(self) -> List[Dict]:
        return list(self._c("investigative_leads").find(
            {"case_id": self.case_id}, {"_id": 0}
        ).sort("confidence", -1).limit(20))

    def _timeline(self, device_id: Optional[str] = None) -> List[Dict]:
        """Note: timeline lives in MongoDB only via AI if SQLite is not consulted here.
        In HIVE the timeline collection may also be mirrored to Mongo by the correlator."""
        filt = {"case_id": self.case_id, "timestamp_utc": {"$ne": ""}}
        if device_id:
            filt["device_id"] = device_id
        return list(self._c("timeline_correlations").find(
            filt, {"_id": 0}).sort("delta_seconds", 1).limit(30))

    def _infra_links(self, entity_value: str) -> List[Dict]:
        filt = {"case_id": self.case_id}
        if entity_value:
            filt["$or"] = [
                {"entity_a_val": {"$regex": re.escape(entity_value), "$options":"i"}},
                {"entity_b_val": {"$regex": re.escape(entity_value), "$options":"i"}},
            ]
        return list(self._c("infrastructure_graph").find(
            filt, {"_id": 0}).limit(20))

    def _all_infra_links(self) -> List[Dict]:
        return list(self._c("infrastructure_graph").find(
            {"case_id": self.case_id}, {"_id": 0}).limit(40))


# ─────────────────────────────────────────────────────────────────────────────
# Prompt Builder
# ─────────────────────────────────────────────────────────────────────────────

class PromptBuilder:
    """
    Converts an InvestigativeContext into a structured text block that
    Nemotron Super can reason over.  Enforces the token budget.
    """

    MAX_CHARS = MAX_CONTEXT_CHARS

    def build(self, ctx: InvestigativeContext,
               history: List[Dict]) -> List[Dict]:
        """Return the full messages list for the NIM API."""
        context_text = self._format_context(ctx)
        user_message = (
            f"INVESTIGATIVE CONTEXT\n"
            f"{'═'*60}\n"
            f"{context_text}\n"
            f"{'═'*60}\n\n"
            f"INVESTIGATOR QUERY\n"
            f"{ctx.query}"
        )
        messages = [{"role": "system", "content": SYSTEM_PROMPT}]
        messages.extend(history[-MAX_HISTORY_TURNS * 2:])  # last N turns
        messages.append({"role": "user", "content": user_message})
        return messages

    def _format_context(self, ctx: InvestigativeContext) -> str:
        sections: List[str] = []
        budget    = self.MAX_CHARS

        def _add(text: str) -> None:
            nonlocal budget
            if budget <= 0:
                return
            sections.append(text[:budget])
            budget -= len(text)

        # ── Case overview ─────────────────────────────────────
        ov = ctx.case_overview
        _add(f"CASE: {ctx.case_id}\n"
              f"Devices Analysed     : {ov.get('devices_analyzed', len(ctx.devices))}\n"
              f"Entities Analysed    : {ov.get('entities_analyzed','?')}\n"
              f"Shared Entities      : {ov.get('shared_entities_found','?')}\n"
              f"Relationships Found  : {ov.get('relationships_found','?')}\n"
              f"Clusters Detected    : {ov.get('clusters_found','?')}\n"
              f"Leads Generated      : {ov.get('leads_generated','?')}\n\n")

        # ── Devices ───────────────────────────────────────────
        if ctx.devices:
            lines = ["DEVICE INVENTORY"]
            for d in ctx.devices[:25]:
                lines.append(
                    f"  • {d.get('device_id','')}  [{d.get('device_type','')}]  "
                    f"{d.get('device_model','(unknown)')}  {d.get('device_os','')}")
            _add("\n".join(lines) + "\n\n")

        # ── Target device ─────────────────────────────────────
        if ctx.target_device:
            _add(self._fmt_device(ctx.target_device, "TARGET DEVICE"))

        # ── Device pair ───────────────────────────────────────
        if ctx.custom.get("device_pair_a"):
            _add(self._fmt_device(ctx.custom["device_pair_a"], "DEVICE A"))
        if ctx.custom.get("device_pair_b"):
            _add(self._fmt_device(ctx.custom["device_pair_b"], "DEVICE B"))
        if ctx.custom.get("relationship"):
            rel = ctx.custom["relationship"]
            _add(f"RELATIONSHIP BETWEEN DEVICES\n"
                  f"  Strength   : {rel.get('strength','')}\n"
                  f"  Score      : {rel.get('confidence_score',0):.2f}\n"
                  f"  Evidence   : {rel.get('evidence_count',0)} shared entity/entities\n"
                  f"  Types      : {', '.join(rel.get('relationship_types',[]))}\n"
                  f"  Shared     : {json.dumps(rel.get('shared_entities',[])[:8], default=str)}\n\n")

        # ── Target cluster ────────────────────────────────────
        if ctx.target_cluster:
            _add(self._fmt_cluster(ctx.target_cluster, "TARGET CLUSTER"))

        # ── All clusters ──────────────────────────────────────
        if ctx.clusters:
            lines = [f"DETECTED CLUSTERS  ({len(ctx.clusters)})"]
            for cl in ctx.clusters[:10]:
                lines.append(
                    f"  • {cl.get('cluster_id','')}  [{cl.get('cluster_type','')}]  "
                    f"{cl.get('device_count',0)} devices  "
                    f"cohesion={cl.get('cohesion_score',0):.2f}")
                lines.append(
                    f"    Members: {', '.join(cl.get('devices',[])[:6])}"
                    + (" …" if len(cl.get('devices',[])) > 6 else ""))
                dom = cl.get("dominant_entities",[])
                if dom:
                    lines.append(
                        f"    Dominant: {', '.join(e['type']+'×'+str(e['count']) for e in dom[:4])}")
            _add("\n".join(lines) + "\n\n")

        # ── Top relationships ─────────────────────────────────
        if ctx.relationships:
            lines = [f"DEVICE RELATIONSHIPS  (top {len(ctx.relationships[:15])})"]
            for rel in ctx.relationships[:15]:
                lines.append(
                    f"  • {rel.get('device_a','')} ↔ {rel.get('device_b','')}  "
                    f"[{rel.get('strength','')}]  score={rel.get('confidence_score',0):.2f}  "
                    f"evidence={rel.get('evidence_count',0)}")
                ets = rel.get("relationship_types",[])
                if ets:
                    lines.append(f"    Types: {', '.join(ets[:5])}")
            _add("\n".join(lines) + "\n\n")

        # ── Shared entities ───────────────────────────────────
        if ctx.entities:
            lines = [f"SHARED ENTITIES  ({len(ctx.entities)})"]
            for e in ctx.entities[:20]:
                lines.append(
                    f"  • [{e.get('entity_type','')}]  "
                    f"{_trunc(e.get('entity_value',''),60)}  "
                    f"devices={e.get('device_count',0)}  "
                    f"significance={e.get('significance',0):.2f}")
            _add("\n".join(lines) + "\n\n")

        # ── Investigative leads ───────────────────────────────
        if ctx.leads:
            lines = [f"INVESTIGATIVE LEADS  ({len(ctx.leads)})"]
            for ld in ctx.leads[:15]:
                lines.append(
                    f"  [{ld.get('priority','')}] {_trunc(ld.get('title',''),70)}")
                lines.append(
                    f"    {_trunc(ld.get('description',''),100)}")
                lines.append(
                    f"    Confidence={ld.get('confidence',0):.2f}  "
                    f"Devices: {', '.join(ld.get('devices',[])[:4])}")
            _add("\n".join(lines) + "\n\n")

        # ── Infrastructure links ──────────────────────────────
        if ctx.infra_links:
            lines = [f"INFRASTRUCTURE LINKS  ({len(ctx.infra_links)})"]
            for lk in ctx.infra_links[:15]:
                lines.append(
                    f"  • {_trunc(lk.get('entity_a_val',''),40)}"
                    f" →[{lk.get('link_type','')}]→ "
                    f"{_trunc(lk.get('entity_b_val',''),40)}")
            _add("\n".join(lines) + "\n\n")

        # ── Timeline correlations ─────────────────────────────
        if ctx.timeline:
            lines = [f"SYNCHRONISED TIMELINE EVENTS  ({len(ctx.timeline)})"]
            for ev in ctx.timeline[:20]:
                ea, eb = ev.get("event_a",{}), ev.get("event_b",{})
                lines.append(
                    f"  Δ{ev.get('delta_seconds',0):.0f}s  "
                    f"{ev.get('device_a','')} [{_trunc(ea.get('event_type',''),20)}] "
                    f"↔ {ev.get('device_b','')} [{_trunc(eb.get('event_type',''),20)}]")
            _add("\n".join(lines) + "\n\n")

        return "\n".join(sections)

    def _fmt_device(self, dev: Dict, label: str) -> str:
        lines = [f"{label}: {dev.get('device_id','')}"]
        lines.append(f"  Type  : {dev.get('device_type','')}  "
                      f"Model : {dev.get('device_model','(unknown)')}  "
                      f"OS: {dev.get('device_os','')}")
        rels = dev.get("relationships",[])
        if rels:
            lines.append(f"  Relationships ({len(rels)}):")
            for r in rels[:5]:
                peer = r.get("device_b") if r.get("device_a")==dev.get("device_id") \
                    else r.get("device_a")
                lines.append(f"    ↔ {peer}  [{r.get('strength','')}]  "
                               f"score={r.get('confidence_score',0):.2f}")
        ents = dev.get("shared_entities",[])
        if ents:
            lines.append(f"  Shared Entities ({len(ents)}):")
            for e in ents[:8]:
                lines.append(f"    [{e.get('entity_type','')}] "
                               f"{_trunc(e.get('entity_value',''),50)}")
        leads = dev.get("leads",[])
        if leads:
            lines.append(f"  Leads ({len(leads)}):")
            for ld in leads[:3]:
                lines.append(f"    [{ld.get('priority','')}] "
                               f"{_trunc(ld.get('title',''),60)}")
        return "\n".join(lines) + "\n\n"

    def _fmt_cluster(self, cl: Dict, label: str) -> str:
        lines = [f"{label}: {cl.get('cluster_id','')}"]
        lines.append(f"  Type     : {cl.get('cluster_type','')}")
        lines.append(f"  Devices  : {cl.get('device_count',0)}")
        lines.append(f"  Cohesion : {cl.get('cohesion_score',0):.2f}")
        lines.append(f"  Int. rels: {cl.get('internal_relationships',0)}")
        devs = cl.get("devices",[])
        lines.append(f"  Members  : {', '.join(devs[:10])}"
                      + (" …" if len(devs) > 10 else ""))
        dom = cl.get("dominant_entities",[])
        if dom:
            lines.append(f"  Dominant entity types:")
            for e in dom[:6]:
                lines.append(f"    {e.get('type','')} × {e.get('count',0)}")
        return "\n".join(lines) + "\n\n"


# ─────────────────────────────────────────────────────────────────────────────
# Analysis Engine
# ─────────────────────────────────────────────────────────────────────────────

class AnalysisEngine:
    """
    Core AI invocation layer.  Calls NIM, parses the structured JSON
    response, validates evidence references, and constructs AIAnalysis.
    """

    def __init__(self, nim: NIMClient, builder: PromptBuilder):
        self.nim     = nim
        self.builder = builder
        self.log     = logging.getLogger("hive.ai.engine")

    def analyze(self, ctx: InvestigativeContext, session: AISession,
                 stream: bool = True) -> AIAnalysis:
        messages = self.builder.build(ctx, session.history)
        analysis = AIAnalysis(
            session_id   = session.session_id,
            case_id      = ctx.case_id,
            query        = ctx.query,
            intent       = ctx.intent,
            model        = self.nim.model,
            temperature  = NIM_TEMPERATURE,
            context_hash = ctx.context_hash,
            investigator = session.investigator,
        )
        t0 = time.time()

        try:
            if stream:
                raw = self._stream_to_terminal(messages)
            else:
                raw, p_tok, c_tok = self.nim.complete(messages)
                analysis.prompt_tokens     = p_tok
                analysis.completion_tokens = c_tok
            analysis.raw_response = raw
            analysis.duration_s   = round(time.time() - t0, 2)
            self._parse_into(raw, analysis)
        except Exception as exc:
            self.log.error(f"NIM inference error: {exc}", exc_info=True)
            analysis.parse_error = str(exc)
            analysis.summary     = f"[Analysis failed: {exc}]"

        return analysis

    def _stream_to_terminal(self, messages: List[Dict]) -> str:
        """Stream tokens to stdout and accumulate full response."""
        print()
        buf: List[str] = []
        for chunk in self.nim.stream(messages):
            print(chunk, end="", flush=True)
            buf.append(chunk)
        print()
        return "".join(buf)

    def _parse_into(self, raw: str, analysis: AIAnalysis) -> None:
        """Parse JSON from AI response into AIAnalysis fields."""
        # Strip markdown fences if present
        text = re.sub(r"^```(?:json)?\s*", "", raw.strip(), flags=re.M)
        text = re.sub(r"\s*```$", "", text.strip(), flags=re.M)

        # Find outermost JSON object
        m = re.search(r"\{[\s\S]+\}", text)
        if m:
            text = m.group(0)

        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            analysis.parse_error = f"JSON parse error: {exc}"
            analysis.summary     = raw[:500]
            return

        analysis.analysis_type           = data.get("analysis_type", analysis.intent)
        analysis.summary                 = data.get("summary", "")
        analysis.key_findings            = data.get("key_findings", [])
        analysis.hypotheses              = data.get("hypotheses", [])
        analysis.risk_assessment         = data.get("risk_assessment", {})
        analysis.key_entities            = data.get("key_entities", [])
        analysis.recommended_actions     = data.get("recommended_actions", [])
        analysis.investigative_questions = data.get("investigative_questions", [])
        analysis.analyst_notes           = data.get("analyst_notes", "")


# ─────────────────────────────────────────────────────────────────────────────
# Audit Store
# ─────────────────────────────────────────────────────────────────────────────

class AuditStore:
    """
    Persists every AI analysis to MongoDB with full provenance.
    Enables investigators to review, challenge, and reproduce AI findings.
    """

    def __init__(self, db):
        self.db  = db
        self.log = logging.getLogger("hive.ai.audit")
        self._ensure_indexes()

    def _ensure_indexes(self) -> None:
        c = self.db
        c.ai_analyses.create_index([("case_id",1),("created_at",-1)])
        c.ai_analyses.create_index([("session_id",1)])
        c.ai_sessions.create_index([("session_id",1)], unique=True)
        c.ai_hypotheses.create_index([("case_id",1)])
        c.ai_recommendations.create_index([("case_id",1),("priority",1)])

    def save_analysis(self, analysis: AIAnalysis) -> str:
        doc = asdict(analysis)
        self.db.ai_analyses.insert_one({**doc, "_id": analysis.analysis_id})
        # Extract hypotheses into their own collection
        for hyp in analysis.hypotheses:
            self.db.ai_hypotheses.insert_one({
                "_id":        str(uuid.uuid4()),
                "case_id":    analysis.case_id,
                "analysis_id":analysis.analysis_id,
                "session_id": analysis.session_id,
                "created_at": analysis.created_at,
                **hyp,
            })
        # Extract recommendations
        for rec in analysis.recommended_actions:
            self.db.ai_recommendations.insert_one({
                "_id":        str(uuid.uuid4()),
                "case_id":    analysis.case_id,
                "analysis_id":analysis.analysis_id,
                "created_at": analysis.created_at,
                **rec,
            })
        return analysis.analysis_id

    def save_session(self, session: AISession) -> None:
        doc = asdict(session)
        doc.pop("history", None)        # don't persist raw conversation to DB
        doc["_id"] = session.session_id
        self.db.ai_sessions.replace_one(
            {"_id": session.session_id}, doc, upsert=True)

    def get_history(self, case_id: str, n: int = 10) -> List[Dict]:
        return list(self.db.ai_analyses.find(
            {"case_id": case_id}, {"_id": 0, "raw_response": 0}
        ).sort("created_at", -1).limit(n))

    def get_recommendations(self, case_id: str,
                              priority: str = "") -> List[Dict]:
        filt = {"case_id": case_id}
        if priority:
            filt["priority"] = priority
        return list(self.db.ai_recommendations.find(
            filt, {"_id": 0}).sort("created_at", -1))


# ─────────────────────────────────────────────────────────────────────────────
# Result Formatter
# ─────────────────────────────────────────────────────────────────────────────

def _print_analysis(a: AIAnalysis, json_mode: bool = False) -> None:
    """Pretty-print a completed AIAnalysis to the terminal."""
    if json_mode:
        print(json.dumps(asdict(a), indent=2, default=str))
        return

    _w = 70
    print(C.bold(f"\n{'═'*_w}"))
    print(C.bold(f"  ANALYSIS  ·  {a.analysis_type or a.intent}"))
    print(C.bold(f"  {a.analysis_id[:8]}  ·  {a.created_at}  ·  "
                   f"model={a.model.split('/')[-1]}  ·  {a.duration_s:.1f}s"))
    print(C.bold(f"{'═'*_w}"))

    if a.summary:
        print(C.bold("\n  SUMMARY"))
        print(textwrap.fill(a.summary, width=_w - 2,
                             initial_indent="  ",
                             subsequent_indent="  "))

    if a.risk_assessment:
        r = a.risk_assessment
        print(C.bold("\n  RISK ASSESSMENT"))
        print(f"  Level      : {C.risk(r.get('level','?'))}")
        print(f"  Confidence : {r.get('confidence',0):.2f}")
        print(f"  Rationale  : {_trunc(r.get('rationale',''),80)}")

    if a.key_findings:
        print(C.bold(f"\n  KEY FINDINGS  ({len(a.key_findings)})"))
        for i, f in enumerate(a.key_findings, 1):
            conf  = f.get("confidence", 0.0)
            col   = (C.red if conf >= 0.8 else C.yellow if conf >= 0.5 else C.dim)
            print(f"  {i:>2}. {col(f'[{conf:.2f}]')}  "
                   f"{_trunc(f.get('finding',''), 65)}")
            for ev in f.get("evidence",[])[:3]:
                print(f"       → {C.dim(_trunc(str(ev),70))}")

    if a.hypotheses:
        print(C.bold(f"\n  HYPOTHESES  ({len(a.hypotheses)})"))
        for i, h in enumerate(a.hypotheses, 1):
            conf = h.get("confidence", 0.0)
            print(f"  {i:>2}. [{conf:.2f}]  "
                   f"{_trunc(h.get('hypothesis',''), 65)}")

    if a.key_entities:
        print(C.bold(f"\n  KEY ENTITIES  ({len(a.key_entities)})"))
        for e in a.key_entities[:8]:
            print(f"  [{e.get('type','')}]  {C.cyan(_trunc(e.get('value',''),45))}  "
                   f"— {_trunc(e.get('significance',''),40)}")

    if a.recommended_actions:
        print(C.bold(f"\n  RECOMMENDED ACTIONS  ({len(a.recommended_actions)})"))
        for i, ac in enumerate(a.recommended_actions, 1):
            pri = ac.get("priority","")
            col = (C.red if pri == "HIGH" else C.yellow if pri == "MEDIUM" else C.green)
            print(f"  {i:>2}. [{col(pri)}]  {_trunc(ac.get('action',''), 65)}")

    if a.investigative_questions:
        print(C.bold(f"\n  OPEN INVESTIGATIVE QUESTIONS"))
        for q in a.investigative_questions[:6]:
            print(f"  ?  {_trunc(q, 75)}")

    if a.analyst_notes:
        print(C.bold("\n  ANALYST NOTES"))
        print(C.dim(textwrap.fill(a.analyst_notes, width=_w - 2,
                                    initial_indent="  ",
                                    subsequent_indent="  ")))

    if a.parse_error:
        print(C.red(f"\n  [PARSE ERROR] {a.parse_error}"))

    print(C.bold(f"\n{'─'*_w}"))


def _export_analysis_md(a: AIAnalysis) -> str:
    """Convert one AIAnalysis to a Markdown section."""
    lines = [
        f"## Analysis: {a.analysis_type or a.intent}",
        f"**ID:** `{a.analysis_id}`  **Generated:** {a.created_at}  "
        f"**Model:** `{a.model}`  **Duration:** {a.duration_s:.1f}s\n",
        f"### Summary\n{a.summary}\n",
    ]
    if a.risk_assessment:
        r = a.risk_assessment
        lines.append(f"### Risk Assessment\n"
                      f"**Level:** {r.get('level','?')}  "
                      f"**Confidence:** {r.get('confidence',0):.2f}  \n"
                      f"{r.get('rationale','')}\n")
    if a.key_findings:
        lines.append("### Key Findings\n")
        for f in a.key_findings:
            lines.append(f"- **[{f.get('confidence',0):.2f}]** {f.get('finding','')}")
            for ev in f.get("evidence",[])[:3]:
                lines.append(f"  - *{ev}*")
        lines.append("")
    if a.hypotheses:
        lines.append("### Hypotheses\n")
        for h in a.hypotheses:
            lines.append(f"- **[{h.get('confidence',0):.2f}]** {h.get('hypothesis','')}")
        lines.append("")
    if a.recommended_actions:
        lines.append("### Recommended Actions\n")
        for ac in a.recommended_actions:
            lines.append(f"- **[{ac.get('priority','')}]** {ac.get('action','')}")
        lines.append("")
    if a.analyst_notes:
        lines.append(f"### Analyst Notes\n{a.analyst_notes}\n")
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Interactive AI Shell
# ─────────────────────────────────────────────────────────────────────────────

class HIVEAIShell(cmd.Cmd):
    intro   = ""
    prompt  = (C.bold(C.magenta("HIVE")) + C.bold(C.cyan("-AI")) + C.dim("> ")
                if sys.stdout.isatty() else "HIVE-AI> ")

    def __init__(self, ai: "HIVEAI"):
        super().__init__()
        self.ai        = ai
        self.json_mode = ai.json_mode
        self._load_history()

    def _load_history(self) -> None:
        try:
            readline.read_history_file(HISTORY_FILE)
            readline.set_history_length(500)
        except Exception:
            pass

    def _save_history(self) -> None:
        try:
            readline.write_history_file(HISTORY_FILE)
        except Exception:
            pass

    def _run_query(self, query: str) -> Optional[AIAnalysis]:
        if not query.strip():
            return None
        return self.ai.ask(query, stream=sys.stdout.isatty())

    # ── Commands ──────────────────────────────────────────────

    def do_ask(self, line: str) -> None:
        """ask <question>  —  Free-form investigative query."""
        if not line.strip():
            print(C.yellow("  Usage: ask <question>"))
            return
        a = self._run_query(line.strip())
        if a and not sys.stdout.isatty():
            _print_analysis(a, self.json_mode)

    def do_follow(self, line: str) -> None:
        """follow <question>  —  Follow-up on the previous analysis."""
        if not line.strip():
            print(C.yellow("  Usage: follow <question>"))
            return
        a = self._run_query(f"[Follow-up] {line.strip()}")
        if a and not sys.stdout.isatty():
            _print_analysis(a, self.json_mode)

    def do_analyze(self, line: str) -> None:
        """analyze device|cluster|entity|rel <target>  —  Targeted analysis."""
        parts = line.strip().split(None, 2)
        if not parts:
            print(C.yellow("  Usage: analyze device <id> | cluster <id> "
                             "| entity <value> | rel <a> <b>"))
            return
        mode = parts[0].lower()
        rest = " ".join(parts[1:]) if len(parts) > 1 else ""

        if mode in ("device",):
            a = self._run_query(f"Provide a full forensic assessment for device {rest}. "
                                  f"Identify its role, relationships, key entities, "
                                  f"and investigative significance.")
        elif mode in ("cluster",):
            a = self._run_query(f"Perform a detailed cluster analysis for {rest}. "
                                  f"Characterise the criminal network, explain member "
                                  f"relationships, and assess operational significance.")
        elif mode in ("entity",):
            a = self._run_query(f"Analyse the investigative significance of entity "
                                  f"'{rest}'. Explain why it matters, which devices it "
                                  f"connects, and what it implies about criminal activity.")
        elif mode in ("rel","relationship"):
            devs = rest.split()
            if len(devs) < 2:
                print(C.yellow("  Usage: analyze rel <device_a> <device_b>"))
                return
            a = self._run_query(f"Explain the relationship between devices "
                                  f"{devs[0]} and {devs[1]}. Detail why they are "
                                  f"linked, confidence of the connection, and what "
                                  f"it implies operationally.")
        else:
            a = self._run_query(line.strip())
        if a and not sys.stdout.isatty():
            _print_analysis(a, self.json_mode)

    def do_brief(self, _: str) -> None:
        """brief  —  Generate a case intelligence brief."""
        a = self._run_query(
            "Generate a comprehensive intelligence brief for this case. "
            "Include: executive summary, key threat actors, criminal infrastructure, "
            "most significant findings, cluster characterisations, risk assessment, "
            "and prioritised recommended investigative actions.")
        if a and not sys.stdout.isatty():
            _print_analysis(a, self.json_mode)

    def do_risks(self, _: str) -> None:
        """risks  —  Risk assessment for all devices and clusters."""
        a = self._run_query(
            "Perform a risk assessment for this entire case. "
            "Rank all detected clusters and devices by threat level. "
            "Identify the highest-risk entities and infrastructure. "
            "Justify each risk rating with specific evidence.")
        if a and not sys.stdout.isatty():
            _print_analysis(a, self.json_mode)

    def do_prioritize(self, _: str) -> None:
        """prioritize  —  AI-ranked investigation target list."""
        a = self._run_query(
            "Rank all devices and clusters in this case by investigative priority. "
            "For each target, explain why it should be prioritised, what evidence "
            "makes it significant, and what specific investigative actions would "
            "yield the most intelligence value.")
        if a and not sys.stdout.isatty():
            _print_analysis(a, self.json_mode)

    def do_hypotheses(self, _: str) -> None:
        """hypotheses  —  Generate investigative hypotheses."""
        a = self._run_query(
            "Based on all available evidence, generate the most plausible "
            "investigative hypotheses. For each hypothesis: state the theory, "
            "list supporting evidence, list contradicting evidence, assign a "
            "confidence score, and suggest what additional evidence would "
            "confirm or refute it.")
        if a and not sys.stdout.isatty():
            _print_analysis(a, self.json_mode)

    def do_timeline(self, line: str) -> None:
        """timeline [device_id]  —  AI timeline reconstruction."""
        device = line.strip()
        query  = (f"Reconstruct the chronological sequence of events for "
                   f"device {device}. " if device else
                   "Reconstruct the chronological sequence of events across "
                   "all devices in this case. ")
        query += ("Identify key moments, behavioural patterns, co-ordinated "
                   "activity, and what the timeline reveals about criminal operations.")
        a = self._run_query(query)
        if a and not sys.stdout.isatty():
            _print_analysis(a, self.json_mode)

    def do_actors(self, _: str) -> None:
        """actors  —  Probable operator / actor attribution."""
        a = self._run_query(
            "Analyse the available evidence to attribute probable operators "
            "or actors. Identify likely individuals or groups controlling "
            "multiple devices, infer roles within the criminal operation, "
            "and highlight the strongest attribution evidence. "
            "Clearly distinguish high-confidence attributions from speculation.")
        if a and not sys.stdout.isatty():
            _print_analysis(a, self.json_mode)

    def do_infrastructure(self, _: str) -> None:
        """infrastructure  —  Map criminal infrastructure."""
        a = self._run_query(
            "Map the criminal infrastructure present in this case. "
            "Identify command-and-control nodes, shared hosting, "
            "communication channels, cryptocurrency infrastructure, "
            "and phishing or malware delivery infrastructure. "
            "Explain how the infrastructure components are interconnected.")
        if a and not sys.stdout.isatty():
            _print_analysis(a, self.json_mode)

    def do_history(self, line: str) -> None:
        """history [n]  —  Show last N AI analyses."""
        n = int(line.strip()) if line.strip().isdigit() else 5
        if not self.ai.audit:
            print(C.dim("  History unavailable (MongoDB not connected)"))
            return
        records = self.ai.audit.get_history(self.ai.case_id, n)
        if not records:
            print(C.dim("  No previous analyses found."))
            return
        print(C.bold(f"\n  ANALYSIS HISTORY  (last {len(records)})"))
        for r in records:
            print(f"  {r.get('created_at','')[:16]}  "
                   f"[{r.get('intent',''):30}]  "
                   f"{_trunc(r.get('summary',''),50)}")

    def do_export(self, line: str) -> None:
        """export [file]  —  Export session analyses to Markdown."""
        outfile = line.strip() or f"hive_ai_session_{self.ai.session.session_id[:8]}.md"
        if not self.ai.audit:
            print(C.dim("  Export unavailable (MongoDB not connected)"))
            return
        records = self.ai.audit.get_history(
            self.ai.case_id, len(self.ai.session.analysis_ids))
        content = (f"# HIVE-AI Investigation Session\n"
                    f"**Case:** {self.ai.case_id}  "
                    f"**Session:** {self.ai.session.session_id[:8]}  "
                    f"**Generated:** {_utcnow()}  "
                    f"**Model:** {self.ai.nim.model}\n\n---\n\n")
        for r in reversed(records):
            a = AIAnalysis(**{k: r.get(k, v)
                               for k, v in asdict(AIAnalysis()).items()})
            content += _export_analysis_md(a) + "\n---\n\n"
        with open(outfile, "w", encoding="utf-8") as fh:
            fh.write(content)
        print(C.green(f"  Session exported → {outfile}"))

    def do_stats(self, _: str) -> None:
        """stats  —  AI usage statistics for this session."""
        s = self.ai.session
        print(C.bold(f"\n  AI SESSION STATISTICS"))
        print(f"  Session ID  : {s.session_id[:8]}")
        print(f"  Case        : {s.case_id}")
        print(f"  Model       : {s.model}")
        print(f"  Started     : {s.started_at}")
        print(f"  Analyses    : {len(s.analysis_ids)}")
        print(f"  Turns       : {s.turn_count}")

    def do_help(self, _: str) -> None:
        """help  —  Show command reference."""
        print(AI_HELP)

    def do_exit(self, _: str) -> bool:
        """exit  —  End the AI session."""
        self._save_history()
        if self.ai.audit:
            self.ai.session.ended_at = _utcnow()
            self.ai.audit.save_session(self.ai.session)
        print(C.dim("\n  AI session closed.\n"))
        return True

    def do_quit(self, line: str) -> bool:
        return self.do_exit(line)

    def do_EOF(self, _: str) -> bool:
        print()
        return self.do_exit("")

    def default(self, line: str) -> None:
        # Let investigators just type questions without the 'ask' prefix
        if line.strip():
            self.do_ask(line)

    def emptyline(self) -> None:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# HIVE-AI  —  Main Orchestrator
# ─────────────────────────────────────────────────────────────────────────────

class HIVEAI:
    """
    Top-level orchestrator.  Wires together all components and exposes
    a clean API for interactive, single-query, and report generation modes.
    """

    def __init__(self, case_id: str,
                  mongo_uri:    str  = DEFAULT_MONGO_URI,
                  mongo_db:     str  = DEFAULT_MONGO_DB,
                  model:        str  = NIM_DEFAULT_MODEL,
                  api_key:      str  = "",
                  nim_base_url: str  = NIM_BASE_URL,
                  investigator: str  = "",
                  json_mode:    bool = False,
                  no_color:     bool = False):
        if no_color:
            C.off()

        self.case_id      = case_id
        self.json_mode    = json_mode
        self.log          = logging.getLogger("hive.ai")

        # NVIDIA NIM
        key = api_key or os.environ.get("NVIDIA_API_KEY", "")
        if not key:
            raise ValueError(
                "NVIDIA API key required.  "
                "Set NVIDIA_API_KEY env var or pass --api-key.")
        self.nim     = NIMClient(key, model, nim_base_url)

        # MongoDB
        self.mongo   = None
        self.db      = None
        self.audit: Optional[AuditStore] = None
        self.retriever: Optional[ContextRetriever] = None

        if HAS_MONGO:
            try:
                self.mongo = pymongo.MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
                self.mongo.admin.command("ping")
                self.db        = self.mongo[mongo_db]
                self.audit     = AuditStore(self.db)
                self.retriever = ContextRetriever(self.db, case_id)
                self.log.info(f"MongoDB connected: {mongo_uri}/{mongo_db}")
            except Exception as exc:
                self.log.warning(f"MongoDB unavailable ({exc}); running without audit store")
        else:
            self.log.warning("pymongo not installed (pip install pymongo)")

        # Sub-components
        self.planner = QueryPlanner()
        self.builder = PromptBuilder()
        self.engine  = AnalysisEngine(self.nim, self.builder)

        # Session
        self.session = AISession(
            case_id      = case_id,
            investigator = investigator or os.environ.get("USER","unknown"),
            model        = model,
        )

    def ask(self, query: str, stream: bool = True) -> AIAnalysis:
        """Execute one investigative query end-to-end."""
        plan = self.planner.plan(query)
        self.log.info(f"Query plan: {plan.intent}  target={plan.target_device or plan.target_cluster or plan.target_entity or '(general)'}")

        if self.retriever:
            ctx = self.retriever.retrieve(plan)
        else:
            # Minimal context without MongoDB
            ctx = InvestigativeContext(
                case_id=self.case_id, query=query, intent=plan.intent)
            ctx.context_hash = _hash(query)

        analysis = self.engine.analyze(ctx, self.session, stream=stream)

        # Update session
        self.session.history.append({"role": "user", "content": query})
        if analysis.summary:
            self.session.history.append({
                "role": "assistant",
                "content": analysis.raw_response[:2000],  # cap history size
            })
        self.session.analysis_ids.append(analysis.analysis_id)
        self.session.turn_count += 1

        # Persist
        if self.audit:
            try:
                self.audit.save_analysis(analysis)
                self.audit.save_session(self.session)
            except Exception as exc:
                self.log.warning(f"Audit store write failed: {exc}")

        if stream:
            _print_analysis(analysis, self.json_mode)
        return analysis

    def interactive(self) -> None:
        print(AI_BANNER.format(v=HIVE_AI_VERSION))
        print(C.bold(f"  Case    : {C.cyan(self.case_id)}"))
        print(C.bold(f"  Model   : {C.magenta(self.nim.model)}"))
        print(C.dim( f"  MongoDB : {'connected' if self.db else 'unavailable'}"))
        print(C.dim( f"  Session : {self.session.session_id[:8]}"))
        print(C.dim( f"  Type your question or 'help' for commands\n"))

        shell = HIVEAIShell(self)
        try:
            shell.cmdloop()
        except KeyboardInterrupt:
            shell.do_exit("")

    def close(self) -> None:
        if self.mongo:
            self.mongo.close()


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def build_cli() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="hive_ai.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "HIVE Platform  —  Stage 5: AI Investigative Intelligence Engine  v"
            + HIVE_AI_VERSION + "\n"
            "Evidence-aware AI analysis powered by NVIDIA NIM · Nemotron Super\n\n"
            "Requires: pip install requests pymongo\n"
            "API key:  export NVIDIA_API_KEY=<your-nim-api-key>"
        ),
        epilog="""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 QUICK-START
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Interactive AI shell:
  export NVIDIA_API_KEY=nvapi-xxxx
  python3 hive_ai.py --case-id CASE-001

Single question:
  python3 hive_ai.py --case-id CASE-001 \\
    --ask "Which devices appear to belong to the same operator?"

Targeted analysis:
  python3 hive_ai.py --case-id CASE-001 \\
    --analyze cluster CLUSTER-A1B2C3D4

Generate intelligence brief (non-streaming, save to file):
  python3 hive_ai.py --case-id CASE-001 --brief \\
    --no-stream --output brief.md

Batch queries from file:
  python3 hive_ai.py --case-id CASE-001 --batch queries.txt

Custom model and MongoDB:
  python3 hive_ai.py --case-id CASE-001 \\
    --model nvidia/llama-3.1-nemotron-70b-instruct \\
    --mongo-uri mongodb://10.0.0.1:27017
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
    )
    g = p.add_argument_group("Case")
    g.add_argument("--case-id", required=True, metavar="ID",
                    help="HIVE case identifier")

    g2 = p.add_argument_group("NVIDIA NIM")
    g2.add_argument("--api-key",  default="",
                     help="NVIDIA NIM API key (or set NVIDIA_API_KEY env var)")
    g2.add_argument("--model",    default=NIM_DEFAULT_MODEL,
                     help=f"NIM model  (default: {NIM_DEFAULT_MODEL})")
    g2.add_argument("--nim-url",  default=NIM_BASE_URL,
                     help=f"NIM base URL  (default: {NIM_BASE_URL})")
    g2.add_argument("--no-stream",action="store_true",
                     help="Disable streaming output (wait for full response)")

    g3 = p.add_argument_group("MongoDB")
    g3.add_argument("--mongo-uri",default=DEFAULT_MONGO_URI,
                     help=f"MongoDB URI  (default: {DEFAULT_MONGO_URI})")
    g3.add_argument("--mongo-db", default=DEFAULT_MONGO_DB,
                     help=f"MongoDB database  (default: {DEFAULT_MONGO_DB})")

    g4 = p.add_argument_group("Execution Mode")
    g4.add_argument("--ask",     metavar="QUESTION",
                     help="Execute a single natural language query and exit")
    g4.add_argument("--analyze", nargs="+", metavar="TARGET",
                     help="Targeted analysis: device|cluster|entity|rel <target>")
    g4.add_argument("--brief",   action="store_true",
                     help="Generate a full case intelligence brief")
    g4.add_argument("--batch",   metavar="FILE",
                     help="Execute queries from a file (one per line)")
    g4.add_argument("--output",  metavar="FILE",
                     help="Write output to file (Markdown)")

    g5 = p.add_argument_group("Output")
    g5.add_argument("--json",     action="store_true",
                     help="Output results as JSON")
    g5.add_argument("--no-color", action="store_true",
                     help="Disable ANSI colour output")
    g5.add_argument("--investigator", default="",
                     help="Investigator name for audit trail")
    g5.add_argument("-v","--verbose", action="store_true",
                     help="Debug logging")
    return p


def main() -> int:
    cli  = build_cli()
    args = cli.parse_args()
    _setup_logging(args.verbose)

    try:
        ai = HIVEAI(
            case_id      = args.case_id,
            mongo_uri    = args.mongo_uri,
            mongo_db     = args.mongo_db,
            model        = args.model,
            api_key      = args.api_key,
            nim_base_url = args.nim_url,
            investigator = args.investigator,
            json_mode    = args.json,
            no_color     = args.no_color,
        )
    except ValueError as exc:
        print(f"[!] {exc}")
        return 1

    do_stream = not args.no_stream

    def _run_and_save(query: str) -> Optional[AIAnalysis]:
        a = ai.ask(query, stream=do_stream)
        if args.output:
            with open(args.output, "a", encoding="utf-8") as fh:
                fh.write(_export_analysis_md(a) + "\n---\n\n")
        return a

    try:
        if args.ask:
            _run_and_save(args.ask)

        elif args.analyze:
            query = " ".join(args.analyze)
            _run_and_save(query)

        elif args.brief:
            _run_and_save(
                "Generate a comprehensive intelligence brief for this entire case. "
                "Include: executive summary, criminal network characterisation, "
                "key threat actors, infrastructure assessment, risk overview, "
                "cluster analysis, top investigative leads, and prioritised "
                "recommended actions.")

        elif args.batch:
            if not os.path.exists(args.batch):
                print(f"[!] Batch file not found: {args.batch}")
                return 1
            with open(args.batch, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    print(C.bold(C.dim(f"\n[BATCH] {line}")))
                    _run_and_save(line)

        else:
            ai.interactive()

    except KeyboardInterrupt:
        print(C.dim("\n  Interrupted."))
    finally:
        ai.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
