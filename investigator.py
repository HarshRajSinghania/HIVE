#!/usr/bin/env python3
"""
investigator.py  —  HIVE Platform · Stage 4: Investigation Query Engine
═══════════════════════════════════════════════════════════════════════════════
High-scale Investigation and Verification Engine  (HIVE)  v1.0.0

The primary interface between investigators and the intelligence produced by
the earlier pipeline stages.  Provides entity search, device profiling,
relationship exploration, cluster analysis, timeline reconstruction, and
formal report generation — with no database knowledge required.

Data sources
  Primary   : MongoDB  (from correlator.py) — relationships, leads, clusters
  Secondary : SQLite   (from parser.py)     — raw artifacts, entities, timeline

Interfaces
  Interactive shell   default mode; readline REPL with history + tab completion
  Single-command      --query "search +447911123456"
  Report generation   --report [summary|device|cluster|leads|full]
  Batch mode          --batch queries.txt
  JSON output         --json  (pipe-friendly machine-readable output)

Pipeline position
  collector → parser → correlator → [investigator.py] → dashboards / AI / reports

Optional dependencies
  pymongo  (pip install pymongo)   — MongoDB access for correlation data

Usage:
  python3 investigator.py --db /evidence/CASE-001/hive_evidence.db --case-id CASE-001
  python3 investigator.py --db /evidence/CASE-001/hive_evidence.db --case-id CASE-001 --query "search +447911"
  python3 investigator.py --db /evidence/CASE-001/hive_evidence.db --case-id CASE-001 --report full --output report.md
  python3 investigator.py --db /evidence/CASE-001/hive_evidence.db --case-id CASE-001 --json --query "leads"
═══════════════════════════════════════════════════════════════════════════════
"""

from __future__ import annotations

import os
import re
import sys
import cmd
import json
import uuid
import shlex
import sqlite3
import logging
import argparse
import datetime
import textwrap
import readline
import itertools
import collections
from dataclasses import dataclass, field, asdict
from typing      import Optional, List, Dict, Any, Tuple, Set

# ── Optional: pymongo ─────────────────────────────────────────────────────────
try:
    import pymongo
    HAS_MONGO = True
except ImportError:
    HAS_MONGO = False

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

HIVE_INV_VERSION = "1.0.0"
HIVE_TOOL        = "HIVE-investigator"
DATE_FMT         = "%Y-%m-%dT%H:%M:%SZ"
DEFAULT_MONGO_URI= "mongodb://localhost:27017"
DEFAULT_MONGO_DB = "hive"
PAGE_WIDTH       = 80
MAX_TIMELINE     = 200     # max events returned in timeline queries
MAX_SEARCH_HITS  = 50      # max artifacts returned per entity search
HISTORY_FILE     = os.path.expanduser("~/.hive_investigator_history")

BANNER = r"""
  ██╗  ██╗██╗██╗   ██╗███████╗
  ██║  ██║██║██║   ██║██╔════╝
  ███████║██║██║   ██║█████╗
  ██╔══██║██║╚██╗ ██╔╝██╔══╝
  ██║  ██║██║ ╚████╔╝ ███████╗
  ╚═╝  ╚═╝╚═╝  ╚═══╝  ╚══════╝  Investigator v{v}
  High-scale Investigation & Verification Engine
"""

HELP_TEXT = """
╔══════════════════════════════════════════════════════════════╗
║  HIVE Investigator  —  Command Reference                     ║
╠══════════════════════════════════════════════════════════════╣
║  SEARCH & PIVOT                                              ║
║    search <value>             Search any entity value        ║
║    pivot  <value>             Expand entity to full network  ║
║    infra  <domain|ip|email>   Trace infrastructure links     ║
║                                                              ║
║  DEVICE INVESTIGATION                                        ║
║    devices                    List all devices in case       ║
║    device  <id>               Full device profile            ║
║    compare <id_a> <id_b>      Side-by-side device comparison ║
║    timeline <id> [--from DATE] [--to DATE]                   ║
║                               Chronological event view       ║
║                                                              ║
║  RELATIONSHIPS & CLUSTERS                                    ║
║    relationships [--device <id>] [--min-score N]             ║
║                               View device relationships      ║
║    clusters                   List all detected clusters     ║
║    cluster <id>               Cluster deep-dive              ║
║                                                              ║
║  LEADS & INTELLIGENCE                                        ║
║    leads [--priority HIGH|MEDIUM|LOW|ALL]                    ║
║                               Investigative leads            ║
║    stats                      Case statistics dashboard      ║
║                                                              ║
║  REPORTS                                                     ║
║    report summary [--output FILE]                            ║
║    report full    [--output FILE]                            ║
║    report device  <id>  [--output FILE]                      ║
║    report cluster <id>  [--output FILE]                      ║
║    report leads   [--output FILE]                            ║
║                                                              ║
║  SYSTEM                                                      ║
║    help                       This help screen               ║
║    exit / quit / EOF (Ctrl-D) Quit the shell                 ║
╚══════════════════════════════════════════════════════════════╝
"""

# ─────────────────────────────────────────────────────────────────────────────
# ANSI Console
# ─────────────────────────────────────────────────────────────────────────────

class C:
    """ANSI colour codes with automatic TTY detection."""
    _CODES = {
        "RED":     "\033[91m",  "GREEN":   "\033[92m",
        "YELLOW":  "\033[93m",  "BLUE":    "\033[94m",
        "MAGENTA": "\033[95m",  "CYAN":    "\033[96m",
        "WHITE":   "\033[97m",  "BOLD":    "\033[1m",
        "DIM":     "\033[2m",   "RESET":   "\033[0m",
    }
    _active = sys.stdout.isatty()

    @classmethod
    def _c(cls, text: str, *codes: str) -> str:
        if not cls._active:
            return text
        prefix = "".join(cls._CODES.get(c, "") for c in codes)
        return f"{prefix}{text}{cls._CODES['RESET']}"

    @classmethod
    def red(cls, t):     return cls._c(t, "RED")
    @classmethod
    def green(cls, t):   return cls._c(t, "GREEN")
    @classmethod
    def yellow(cls, t):  return cls._c(t, "YELLOW")
    @classmethod
    def cyan(cls, t):    return cls._c(t, "CYAN")
    @classmethod
    def blue(cls, t):    return cls._c(t, "BLUE")
    @classmethod
    def bold(cls, t):    return cls._c(t, "BOLD")
    @classmethod
    def dim(cls, t):     return cls._c(t, "DIM")
    @classmethod
    def magenta(cls, t): return cls._c(t, "MAGENTA")

    @classmethod
    def priority(cls, p: str) -> str:
        return {
            "HIGH":          cls._c(p, "RED",    "BOLD"),
            "MEDIUM":        cls._c(p, "YELLOW", "BOLD"),
            "LOW":           cls._c(p, "GREEN"),
            "INFORMATIONAL": cls._c(p, "DIM"),
        }.get(p, p)

    @classmethod
    def strength(cls, s: str) -> str:
        return {
            "DEFINITIVE": cls._c(s, "RED",    "BOLD"),
            "STRONG":     cls._c(s, "YELLOW", "BOLD"),
            "MODERATE":   cls._c(s, "CYAN"),
            "WEAK":       cls._c(s, "DIM"),
        }.get(s, s)

    @classmethod
    def no_color(cls) -> None:
        cls._active = False


def _sep(char: str = "─", width: int = PAGE_WIDTH) -> str:
    return char * width


def _box_line(text: str, width: int = PAGE_WIDTH) -> str:
    inner = width - 4
    return f"║  {text[:inner].ljust(inner)}  ║"


def _print(*args, **kwargs) -> None:
    print(*args, **kwargs)


# ─────────────────────────────────────────────────────────────────────────────
# Result Data Models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class EntityHit:
    entity_type:   str
    entity_value:  str
    device_id:     str
    artifact_type: str
    first_seen:    str
    confidence:    float = 1.0
    context:       str   = ""


@dataclass
class EntitySearchResult:
    query:             str
    entity_type:       str         = "UNKNOWN"
    entity_value:      str         = ""
    devices:           List[str]   = field(default_factory=list)
    artifact_types:    List[str]   = field(default_factory=list)
    hits:              List[EntityHit] = field(default_factory=list)
    relationships:     List[Dict]  = field(default_factory=list)
    leads:             List[Dict]  = field(default_factory=list)
    infra_links:       List[Dict]  = field(default_factory=list)
    total_occurrences: int         = 0
    first_seen:        str         = ""
    last_seen:         str         = ""
    significance:      float       = 0.0
    searched_at:       str         = field(default_factory=lambda: _utcnow())


@dataclass
class DeviceProfile:
    device_id:         str
    case_id:           str           = ""
    device_type:       str           = ""
    device_model:      str           = ""
    device_os:         str           = ""
    acquisition_id:    str           = ""
    entity_counts:     Dict[str,int] = field(default_factory=dict)
    top_entities:      List[Dict]    = field(default_factory=list)
    relationships:     List[Dict]    = field(default_factory=list)
    cluster_ids:       List[str]     = field(default_factory=list)
    leads:             List[Dict]    = field(default_factory=list)
    timeline_summary:  Dict          = field(default_factory=dict)
    artifact_counts:   Dict[str,int] = field(default_factory=dict)


@dataclass
class DeviceComparison:
    device_a:          str
    device_b:          str
    shared_entities:   List[Dict]  = field(default_factory=list)
    unique_to_a:       List[Dict]  = field(default_factory=list)
    unique_to_b:       List[Dict]  = field(default_factory=list)
    relationship:      Optional[Dict] = None
    timeline_overlaps: List[Dict]  = field(default_factory=list)
    confidence_score:  float       = 0.0
    verdict:           str         = "NO LINK"


@dataclass
class PivotResult:
    seed_entity_type:  str
    seed_entity_value: str
    direct_devices:    List[str]   = field(default_factory=list)
    second_degree:     List[str]   = field(default_factory=list)
    connected_entities:List[Dict]  = field(default_factory=list)
    all_relationships: List[Dict]  = field(default_factory=list)
    pivot_depth:       int         = 1


@dataclass
class CaseStats:
    case_id:          str
    devices:          int = 0
    artifacts:        int = 0
    entities:         int = 0
    unique_phones:    int = 0
    unique_emails:    int = 0
    unique_ips:       int = 0
    unique_domains:   int = 0
    unique_crypto:    int = 0
    relationships:    int = 0
    clusters:         int = 0
    leads_high:       int = 0
    leads_medium:     int = 0
    leads_low:        int = 0
    timeline_events:  int = 0
    parse_errors:     int = 0


# ─────────────────────────────────────────────────────────────────────────────
# Utility
# ─────────────────────────────────────────────────────────────────────────────

def _utcnow() -> str:
    return datetime.datetime.utcnow().strftime(DATE_FMT)


def _trunc(s: str, n: int) -> str:
    return s[:n - 1] + "…" if len(s) > n else s


def _detect_entity_type(value: str) -> str:
    """Classify a raw search string into the most likely EntityType."""
    v = value.strip()
    if re.fullmatch(r"0x[a-fA-F0-9]{40}", v):
        return "CRYPTO_ETH"
    if re.fullmatch(r"(?:1|3)[a-km-zA-HJ-NP-Z1-9]{25,34}", v):
        return "CRYPTO_BTC"
    if re.fullmatch(r"bc1[ac-hj-np-z02-9]{11,71}", v, re.I):
        return "CRYPTO_BTC"
    if re.fullmatch(r"[0-9a-fA-F]{64}", v):
        return "HASH_SHA256"
    if re.fullmatch(r"[0-9a-fA-F]{40}", v):
        return "HASH_SHA1"
    if re.fullmatch(r"[0-9a-fA-F]{32}", v):
        return "HASH_MD5"
    if re.fullmatch(r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)", v):
        return "IPV4"
    if re.search(r"(?:[0-9a-fA-F]{1,4}:){2,}", v):
        return "IPV6"
    if re.fullmatch(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", v):
        return "EMAIL"
    if re.fullmatch(r"https?://.+", v, re.I):
        return "URL"
    if re.fullmatch(r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}", v):
        return "DOMAIN"
    if re.fullmatch(r"\+?[1-9]\d{6,14}", v.replace(" ","")):
        return "PHONE"
    if re.fullmatch(r"\d{15}", v):
        return "IMEI"
    if re.fullmatch(r"(?:[0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}", v, re.I):
        return "MAC_ADDRESS"
    if re.fullmatch(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){2,}", v):
        return "ANDROID_PACKAGE"
    return "UNKNOWN"


def _fmt_table(headers: List[str], rows: List[List[str]],
                col_widths: Optional[List[int]] = None,
                max_w: int = 40) -> str:
    """Simple fixed-width table renderer."""
    widths = col_widths or [max(len(h), max((len(str(r[i])) for r in rows if i < len(r)),
                                             default=0))
                             for i, h in enumerate(headers)]
    widths = [min(w, max_w) for w in widths]

    def _row(cells: List[str]) -> str:
        return "  ".join(str(c)[:widths[i]].ljust(widths[i])
                          for i, c in enumerate(cells) if i < len(widths))

    sep = _sep("─", sum(widths) + 2 * (len(widths) - 1))
    lines = [sep, C.bold(_row(headers)), sep]
    for r in rows:
        lines.append(_row([str(c) for c in r]))
    lines.append(sep)
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Database Adapters
# ─────────────────────────────────────────────────────────────────────────────

class SQLiteAdapter:
    """Read-only adapter for the parser.py evidence database."""

    def __init__(self, db_path: str):
        if not os.path.exists(db_path):
            raise FileNotFoundError(f"Evidence DB not found: {db_path}")
        self.conn = sqlite3.connect(
            f"file:{db_path}?mode=ro", uri=True, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.log = logging.getLogger("hive.inv.sqlite")

    def _q(self, sql: str, params: tuple = ()) -> List[Dict]:
        try:
            cur = self.conn.cursor()
            cur.execute(sql, params)
            return [dict(r) for r in cur.fetchall()]
        except sqlite3.Error as exc:
            self.log.error(f"SQLite: {exc}")
            return []

    def devices(self, case_id: str) -> List[Dict]:
        return self._q("SELECT * FROM devices WHERE case_id=?", (case_id,))

    def all_case_ids(self) -> List[str]:
        rows = self._q("SELECT DISTINCT case_id FROM devices")
        return [r["case_id"] for r in rows]

    def entity_search(self, case_id: str, value: str,
                       limit: int = MAX_SEARCH_HITS) -> List[Dict]:
        return self._q(
            "SELECT * FROM entities WHERE case_id=? AND entity_value LIKE ? LIMIT ?",
            (case_id, f"%{value}%", limit))

    def entity_search_exact(self, case_id: str, value: str) -> List[Dict]:
        return self._q(
            "SELECT * FROM entities WHERE case_id=? AND LOWER(entity_value)=LOWER(?)",
            (case_id, value))

    def entities_for_device(self, case_id: str,
                             device_id: str) -> List[Dict]:
        return self._q(
            "SELECT entity_type, entity_value, COUNT(*) as occurrences, "
            "MIN(first_seen) as first_seen, MAX(confidence) as confidence "
            "FROM entities WHERE case_id=? AND device_id=? "
            "GROUP BY entity_type, entity_value ORDER BY occurrences DESC",
            (case_id, device_id))

    def entity_counts_by_type(self, case_id: str,
                               device_id: str) -> Dict[str, int]:
        rows = self._q(
            "SELECT entity_type, COUNT(DISTINCT entity_value) as n "
            "FROM entities WHERE case_id=? AND device_id=? GROUP BY entity_type",
            (case_id, device_id))
        return {r["entity_type"]: r["n"] for r in rows}

    def timeline(self, case_id: str, device_id: Optional[str] = None,
                  from_ts: str = "", to_ts: str = "",
                  event_type: str = "",
                  limit: int = MAX_TIMELINE) -> List[Dict]:
        clauses = ["case_id=?", "timestamp_utc != ''"]
        params: List = [case_id]
        if device_id:
            clauses.append("device_id=?"); params.append(device_id)
        if from_ts:
            clauses.append("timestamp_utc >= ?"); params.append(from_ts)
        if to_ts:
            clauses.append("timestamp_utc <= ?"); params.append(to_ts)
        if event_type:
            clauses.append("event_type=?"); params.append(event_type)
        sql = (f"SELECT event_id, case_id, device_id, timestamp_utc, "
               f"event_type, description, actor, target, source_file "
               f"FROM timeline WHERE {' AND '.join(clauses)} "
               f"ORDER BY timestamp_utc LIMIT ?")
        params.append(limit)
        return self._q(sql, tuple(params))

    def timeline_summary(self, case_id: str, device_id: str) -> Dict:
        rows = self._q(
            "SELECT event_type, COUNT(*) as n FROM timeline "
            "WHERE case_id=? AND device_id=? GROUP BY event_type",
            (case_id, device_id))
        min_ts = self._q(
            "SELECT MIN(timestamp_utc) as ts FROM timeline "
            "WHERE case_id=? AND device_id=? AND timestamp_utc!=''",
            (case_id, device_id))
        max_ts = self._q(
            "SELECT MAX(timestamp_utc) as ts FROM timeline "
            "WHERE case_id=? AND device_id=? AND timestamp_utc!=''",
            (case_id, device_id))
        return {
            "by_type":  {r["event_type"]: r["n"] for r in rows},
            "earliest": min_ts[0]["ts"] if min_ts else "",
            "latest":   max_ts[0]["ts"] if max_ts else "",
            "total":    sum(r["n"] for r in rows),
        }

    def artifact_counts(self, case_id: str, device_id: str) -> Dict[str, int]:
        rows = self._q(
            "SELECT artifact_type, COUNT(*) as n FROM artifacts "
            "WHERE case_id=? AND device_id=? GROUP BY artifact_type",
            (case_id, device_id))
        return {r["artifact_type"]: r["n"] for r in rows}

    def global_stats(self, case_id: str) -> Dict:
        def _cnt(sql, params=()):
            r = self._q(sql, params)
            return r[0]["n"] if r else 0
        return {
            "devices":   _cnt("SELECT COUNT(*) as n FROM devices WHERE case_id=?",
                               (case_id,)),
            "artifacts": _cnt("SELECT COUNT(*) as n FROM artifacts WHERE case_id=?",
                               (case_id,)),
            "entities":  _cnt("SELECT COUNT(*) as n FROM entities WHERE case_id=?",
                               (case_id,)),
            "timeline":  _cnt("SELECT COUNT(*) as n FROM timeline WHERE case_id=?",
                               (case_id,)),
            "errors":    _cnt("SELECT COUNT(*) as n FROM parse_errors WHERE case_id=?",
                               (case_id,)),
        }

    def entity_type_stats(self, case_id: str) -> Dict[str, int]:
        rows = self._q(
            "SELECT entity_type, COUNT(DISTINCT entity_value) as n "
            "FROM entities WHERE case_id=? GROUP BY entity_type",
            (case_id,))
        return {r["entity_type"]: r["n"] for r in rows}

    def close(self) -> None:
        self.conn.close()


class MongoAdapter:
    """Adapter for the MongoDB correlation database."""

    def __init__(self, uri: str, db_name: str):
        self.client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=5000)
        self.client.admin.command("ping")
        self.db  = self.client[db_name]
        self.log = logging.getLogger("hive.inv.mongo")

    def _col(self, name: str):
        return self.db[name]

    def relationships_for_device(self, case_id: str,
                                  device_id: str) -> List[Dict]:
        return list(self._col("device_relationships").find(
            {"case_id": case_id,
             "$or": [{"device_a": device_id}, {"device_b": device_id}]},
            {"_id": 0}).sort("confidence_score", -1))

    def all_relationships(self, case_id: str,
                           min_score: float = 0.0) -> List[Dict]:
        filt = {"case_id": case_id}
        if min_score > 0:
            filt["confidence_score"] = {"$gte": min_score}
        return list(self._col("device_relationships").find(
            filt, {"_id": 0}).sort("confidence_score", -1))

    def relationship_between(self, case_id: str,
                              dev_a: str, dev_b: str) -> Optional[Dict]:
        a, b = sorted([dev_a, dev_b])
        r = self._col("device_relationships").find_one(
            {"case_id": case_id, "device_a": a, "device_b": b}, {"_id": 0})
        if not r:
            r = self._col("device_relationships").find_one(
                {"case_id": case_id,
                 "$or": [{"device_a": dev_a, "device_b": dev_b},
                          {"device_a": dev_b, "device_b": dev_a}]},
                {"_id": 0})
        return r

    def leads(self, case_id: str, priority: str = "") -> List[Dict]:
        filt = {"case_id": case_id}
        if priority and priority != "ALL":
            filt["priority"] = priority
        return list(self._col("investigative_leads").find(
            filt, {"_id": 0}).sort("confidence", -1))

    def clusters(self, case_id: str) -> List[Dict]:
        return list(self._col("device_clusters").find(
            {"case_id": case_id}, {"_id": 0}).sort("device_count", -1))

    def cluster_by_id(self, cluster_id: str) -> Optional[Dict]:
        return self._col("device_clusters").find_one(
            {"cluster_id": cluster_id}, {"_id": 0})

    def clusters_for_device(self, case_id: str,
                             device_id: str) -> List[Dict]:
        return list(self._col("device_clusters").find(
            {"case_id": case_id, "devices": device_id}, {"_id": 0}))

    def entity_network(self, case_id: str,
                        entity_value: str) -> Optional[Dict]:
        return self._col("entity_network").find_one(
            {"case_id": case_id,
             "entity_value": {"$regex": re.escape(entity_value), "$options": "i"}},
            {"_id": 0})

    def entity_network_for_device(self, case_id: str,
                                   device_id: str) -> List[Dict]:
        return list(self._col("entity_network").find(
            {"case_id": case_id, "devices": device_id, "device_count": {"$gte": 2}},
            {"_id": 0}).sort("significance", -1).limit(50))

    def infra_links(self, case_id: str,
                     entity_value: str) -> List[Dict]:
        return list(self._col("infrastructure_graph").find(
            {"case_id": case_id,
             "$or": [{"entity_a_val": {"$regex": re.escape(entity_value), "$options":"i"}},
                     {"entity_b_val": {"$regex": re.escape(entity_value), "$options":"i"}}]},
            {"_id": 0}))

    def leads_for_devices(self, case_id: str,
                           device_ids: List[str]) -> List[Dict]:
        return list(self._col("investigative_leads").find(
            {"case_id": case_id, "devices": {"$in": device_ids}},
            {"_id": 0}).sort("confidence", -1))

    def timeline_correlations_between(self, case_id: str,
                                       dev_a: str, dev_b: str) -> List[Dict]:
        return list(self._col("timeline_correlations").find(
            {"case_id": case_id,
             "$or": [{"device_a": dev_a, "device_b": dev_b},
                     {"device_a": dev_b, "device_b": dev_a}]},
            {"_id": 0}).sort("sync_score", -1).limit(20))

    def run_stats(self, case_id: str) -> Optional[Dict]:
        return self._col("correlation_runs").find_one(
            {"case_id": case_id}, {"_id": 0},
            sort=[("completed_at", -1)])

    def close(self) -> None:
        self.client.close()


# ─────────────────────────────────────────────────────────────────────────────
# Query Engine
# ─────────────────────────────────────────────────────────────────────────────

class QueryEngine:
    """
    Unified query layer that merges data from MongoDB (correlations) and
    SQLite (raw evidence) into structured result objects.

    Falls back gracefully to SQLite-only mode when MongoDB is unavailable.
    """

    def __init__(self, sqlite: SQLiteAdapter,
                  mongo: Optional[MongoAdapter],
                  case_id: str):
        self.db      = sqlite
        self.mg      = mongo
        self.case_id = case_id
        self.log     = logging.getLogger("hive.inv.query")

    # ── Entity search ─────────────────────────────────────────

    def search(self, query: str) -> EntitySearchResult:
        etype  = _detect_entity_type(query)
        result = EntitySearchResult(query=query, entity_type=etype,
                                     entity_value=query)

        # SQLite: raw entity hits
        rows = self.db.entity_search_exact(self.case_id, query)
        if not rows:
            rows = self.db.entity_search(self.case_id, query)

        result.hits = [EntityHit(
            entity_type   = r.get("entity_type",""),
            entity_value  = r.get("entity_value",""),
            device_id     = r.get("device_id",""),
            artifact_type = r.get("artifact_type",""),
            first_seen    = r.get("first_seen",""),
            confidence    = r.get("confidence", 1.0),
            context       = r.get("context",""),
        ) for r in rows[:MAX_SEARCH_HITS]]

        result.devices        = list({h.device_id for h in result.hits})
        result.artifact_types = list({h.artifact_type for h in result.hits})
        result.total_occurrences = len(rows)

        ts_vals = sorted(h.first_seen for h in result.hits if h.first_seen)
        result.first_seen = ts_vals[0]  if ts_vals else ""
        result.last_seen  = ts_vals[-1] if ts_vals else ""

        # MongoDB: correlations, leads, infra
        if self.mg:
            net = self.mg.entity_network(self.case_id, query)
            if net:
                result.significance = net.get("significance", 0.0)
                result.devices      = net.get("devices", result.devices)

            for dev in result.devices[:10]:
                rels = self.mg.relationships_for_device(self.case_id, dev)
                result.relationships.extend(rels)

            result.leads      = self.mg.leads_for_devices(
                self.case_id, result.devices)
            result.infra_links= self.mg.infra_links(self.case_id, query)

        # Deduplicate relationships
        seen_rids: Set[str] = set()
        uniq_rels = []
        for r in result.relationships:
            rid = r.get("relationship_id", "")
            if rid not in seen_rids:
                seen_rids.add(rid)
                uniq_rels.append(r)
        result.relationships = uniq_rels

        return result

    # ── Device profile ────────────────────────────────────────

    def device_profile(self, device_id: str) -> Optional[DeviceProfile]:
        devs = [d for d in self.db.devices(self.case_id)
                 if d.get("device_id") == device_id]
        if not devs:
            return None
        dev = devs[0]
        manifest = {}
        try:
            manifest = json.loads(dev.get("manifest_json") or "{}")
        except Exception:
            pass

        profile = DeviceProfile(
            device_id      = device_id,
            case_id        = self.case_id,
            device_type    = dev.get("device_type", ""),
            device_model   = dev.get("device_model", manifest.get("device_model","")),
            device_os      = dev.get("device_os",    manifest.get("device_os","")),
            acquisition_id = dev.get("acquisition_id",""),
        )
        profile.entity_counts   = self.db.entity_counts_by_type(self.case_id, device_id)
        profile.top_entities    = self.db.entities_for_device(self.case_id, device_id)[:20]
        profile.timeline_summary= self.db.timeline_summary(self.case_id, device_id)
        profile.artifact_counts = self.db.artifact_counts(self.case_id, device_id)

        if self.mg:
            profile.relationships = self.mg.relationships_for_device(
                self.case_id, device_id)
            profile.cluster_ids   = [c.get("cluster_id","")
                                       for c in self.mg.clusters_for_device(
                                           self.case_id, device_id)]
            profile.leads         = self.mg.leads_for_devices(
                self.case_id, [device_id])

        return profile

    # ── Device listing ────────────────────────────────────────

    def list_devices(self) -> List[Dict]:
        return self.db.devices(self.case_id)

    # ── Timeline ──────────────────────────────────────────────

    def timeline(self, device_id: str, from_ts: str = "",
                  to_ts: str = "", event_type: str = "") -> List[Dict]:
        return self.db.timeline(self.case_id, device_id,
                                  from_ts=from_ts, to_ts=to_ts,
                                  event_type=event_type)

    def full_timeline(self, from_ts: str = "",
                       to_ts: str = "") -> List[Dict]:
        return self.db.timeline(self.case_id, from_ts=from_ts, to_ts=to_ts,
                                  limit=MAX_TIMELINE * 5)

    # ── Relationships ─────────────────────────────────────────

    def relationships(self, device_id: Optional[str] = None,
                       min_score: float = 0.0) -> List[Dict]:
        if not self.mg:
            return []
        if device_id:
            return self.mg.relationships_for_device(self.case_id, device_id)
        return self.mg.all_relationships(self.case_id, min_score)

    # ── Compare devices ───────────────────────────────────────

    def compare(self, dev_a: str, dev_b: str) -> DeviceComparison:
        cmp = DeviceComparison(device_a=dev_a, device_b=dev_b)

        ents_a = {(r["entity_type"], r["entity_value"].lower())
                   for r in self.db.entities_for_device(self.case_id, dev_a)}
        ents_b = {(r["entity_type"], r["entity_value"].lower())
                   for r in self.db.entities_for_device(self.case_id, dev_b)}

        shared = ents_a & ents_b
        cmp.shared_entities = [{"type": t, "value": v} for t, v in shared]
        cmp.unique_to_a     = [{"type": t, "value": v} for t, v in ents_a - ents_b]
        cmp.unique_to_b     = [{"type": t, "value": v} for t, v in ents_b - ents_a]

        if self.mg:
            cmp.relationship = self.mg.relationship_between(
                self.case_id, dev_a, dev_b)
            cmp.timeline_overlaps = self.mg.timeline_correlations_between(
                self.case_id, dev_a, dev_b)

        if cmp.relationship:
            cmp.confidence_score = cmp.relationship.get("confidence_score", 0.0)
            cmp.verdict          = cmp.relationship.get("strength", "WEAK")
        elif shared:
            cmp.confidence_score = min(0.5, len(shared) * 0.1)
            cmp.verdict          = "PARTIAL MATCH"
        else:
            cmp.verdict          = "NO LINK"

        return cmp

    # ── Pivot ─────────────────────────────────────────────────

    def pivot(self, entity_value: str) -> PivotResult:
        etype = _detect_entity_type(entity_value)
        pr    = PivotResult(seed_entity_type=etype,
                             seed_entity_value=entity_value)

        # Direct devices from SQLite
        hits = self.db.entity_search_exact(self.case_id, entity_value)
        pr.direct_devices = list({h["device_id"] for h in hits})

        if self.mg:
            rels = []
            for dev in pr.direct_devices:
                rels.extend(self.mg.relationships_for_device(
                    self.case_id, dev))
            pr.all_relationships = rels

            # Second-degree devices
            second: Set[str] = set()
            for r in rels:
                second.add(r.get("device_a",""))
                second.add(r.get("device_b",""))
            second -= set(pr.direct_devices)
            pr.second_degree = list(second)

            # Connected entities (shared across direct devices)
            for dev in pr.direct_devices:
                pr.connected_entities.extend(
                    self.mg.entity_network_for_device(self.case_id, dev))

        pr.pivot_depth = 2 if pr.second_degree else 1
        return pr

    # ── Leads ─────────────────────────────────────────────────

    def leads(self, priority: str = "") -> List[Dict]:
        if self.mg:
            return self.mg.leads(self.case_id, priority)
        return []

    # ── Clusters ─────────────────────────────────────────────

    def clusters(self) -> List[Dict]:
        if self.mg:
            return self.mg.clusters(self.case_id)
        return []

    def cluster(self, cluster_id: str) -> Optional[Dict]:
        if self.mg:
            return self.mg.cluster_by_id(cluster_id)
        return None

    # ── Infrastructure ────────────────────────────────────────

    def infra(self, entity_value: str) -> List[Dict]:
        if self.mg:
            return self.mg.infra_links(self.case_id, entity_value)
        return []

    # ── Stats ─────────────────────────────────────────────────

    def stats(self) -> CaseStats:
        raw   = self.db.global_stats(self.case_id)
        etype = self.db.entity_type_stats(self.case_id)
        cs    = CaseStats(
            case_id       = self.case_id,
            devices       = raw.get("devices", 0),
            artifacts     = raw.get("artifacts", 0),
            entities      = raw.get("entities", 0),
            timeline_events=raw.get("timeline", 0),
            parse_errors  = raw.get("errors", 0),
            unique_phones  = etype.get("PHONE", 0),
            unique_emails  = etype.get("EMAIL", 0),
            unique_ips     = etype.get("IPV4", 0) + etype.get("IPV6", 0),
            unique_domains = etype.get("DOMAIN", 0),
            unique_crypto  = (etype.get("CRYPTO_BTC", 0) +
                               etype.get("CRYPTO_ETH", 0)),
        )
        if self.mg:
            leads = self.mg.leads(self.case_id)
            cs.relationships = len(self.mg.all_relationships(self.case_id))
            cs.clusters      = len(self.mg.clusters(self.case_id))
            cs.leads_high    = sum(1 for l in leads if l.get("priority")=="HIGH")
            cs.leads_medium  = sum(1 for l in leads if l.get("priority")=="MEDIUM")
            cs.leads_low     = sum(1 for l in leads if l.get("priority")=="LOW")
        return cs


# ─────────────────────────────────────────────────────────────────────────────
# Result Formatter
# ─────────────────────────────────────────────────────────────────────────────

class Formatter:
    """Converts structured result objects into human-readable terminal output."""

    def search_result(self, r: EntitySearchResult, json_mode: bool = False) -> str:
        if json_mode:
            return json.dumps(asdict(r), indent=2, default=str)
        lines = []
        lines.append(C.bold(f"\n  ENTITY SEARCH  —  {C.cyan(r.query)}"))
        lines.append(f"  Type        : {C.yellow(r.entity_type)}")
        lines.append(f"  Occurrences : {r.total_occurrences}")
        lines.append(f"  Devices     : {C.bold(str(len(r.devices)))}  "
                      f"→  {', '.join(C.cyan(d) for d in r.devices[:6])}"
                      + (" …" if len(r.devices) > 6 else ""))
        if r.first_seen:
            lines.append(f"  First seen  : {r.first_seen}")
        if r.last_seen and r.last_seen != r.first_seen:
            lines.append(f"  Last seen   : {r.last_seen}")
        if r.significance:
            lines.append(f"  Significance: {r.significance:.2f}")
        if r.hits:
            lines.append(f"\n  {C.bold('ARTIFACT HITS')}  ({len(r.hits)} shown)")
            rows = [[h.device_id, h.artifact_type, h.first_seen[:10],
                     _trunc(h.entity_value, 40)]
                     for h in r.hits[:15]]
            lines.append(_fmt_table(
                ["Device", "Artifact Type", "Date", "Value"],
                rows, [22, 24, 10, 40]))
        if r.relationships:
            lines.append(f"\n  {C.bold('RELATIONSHIPS')}  ({len(r.relationships)} found)")
            for rel in r.relationships[:5]:
                lines.append(
                    f"    {C.cyan(rel.get('device_a',''))} ↔ "
                    f"{C.cyan(rel.get('device_b',''))}  "
                    f"{C.strength(rel.get('strength',''))}  "
                    f"score={rel.get('confidence_score',0):.2f}")
        if r.leads:
            lines.append(f"\n  {C.bold('RELATED LEADS')}  ({len(r.leads)} found)")
            for lead in r.leads[:3]:
                lines.append(f"    [{C.priority(lead.get('priority',''))}]  "
                               f"{_trunc(lead.get('title',''), 70)}")
        if r.infra_links:
            lines.append(f"\n  {C.bold('INFRASTRUCTURE LINKS')}  "
                          f"({len(r.infra_links)})")
            for lnk in r.infra_links[:5]:
                lines.append(f"    {lnk.get('entity_a_val','')} "
                               f"→[{lnk.get('link_type','')}]→ "
                               f"{lnk.get('entity_b_val','')}")
        return "\n".join(lines)

    def device_profile(self, p: DeviceProfile, json_mode: bool = False) -> str:
        if json_mode:
            return json.dumps(asdict(p), indent=2, default=str)
        lines = []
        lines.append(C.bold(f"\n  DEVICE PROFILE  —  {C.cyan(p.device_id)}"))
        lines.append(_sep())
        lines.append(f"  Type        : {p.device_type}")
        lines.append(f"  Model       : {p.device_model or '(unknown)'}")
        lines.append(f"  OS          : {p.device_os or '(unknown)'}")
        lines.append(f"  Acq. ID     : {p.acquisition_id}")
        if p.cluster_ids:
            lines.append(f"  Clusters    : {', '.join(p.cluster_ids)}")

        # Entity inventory
        lines.append(f"\n  {C.bold('ENTITY INVENTORY')}")
        for etype, count in sorted(p.entity_counts.items(),
                                     key=lambda x: x[1], reverse=True):
            bar = "█" * min(20, count // max(1, max(p.entity_counts.values()) // 20))
            lines.append(f"    {etype:<20} {count:>5}  {C.cyan(bar)}")

        # Top entities
        if p.top_entities:
            lines.append(f"\n  {C.bold('TOP ENTITIES')}  (by occurrence)")
            rows = [[e.get("entity_type",""), _trunc(e.get("entity_value",""),40),
                     e.get("occurrences",1), f"{e.get('confidence',1.0):.2f}"]
                     for e in p.top_entities[:12]]
            lines.append(_fmt_table(["Type","Value","n","Conf"],
                                     rows, [18,40,5,5]))

        # Relationships
        if p.relationships:
            lines.append(f"\n  {C.bold('RELATIONSHIPS')}  ({len(p.relationships)})")
            for rel in p.relationships[:8]:
                peer = (rel.get("device_b") if rel.get("device_a") == p.device_id
                         else rel.get("device_a"))
                lines.append(
                    f"    ↔ {C.cyan(_trunc(peer or '',30)):<32} "
                    f"{C.strength(rel.get('strength','')):<12}  "
                    f"score={rel.get('confidence_score',0):.2f}  "
                    f"evidence={rel.get('evidence_count',0)}")

        # Timeline
        tl = p.timeline_summary
        if tl.get("total"):
            lines.append(f"\n  {C.bold('TIMELINE')}  "
                          f"({tl['total']} events  "
                          f"{tl.get('earliest','')[:10]} → "
                          f"{tl.get('latest','')[:10]})")
            for etype, cnt in sorted(tl.get("by_type",{}).items(),
                                      key=lambda x: x[1], reverse=True)[:8]:
                lines.append(f"    {etype:<30} {cnt}")

        # Leads
        if p.leads:
            lines.append(f"\n  {C.bold('INVESTIGATIVE LEADS')}  ({len(p.leads)})")
            for lead in p.leads[:5]:
                lines.append(f"    [{C.priority(lead.get('priority',''))}]  "
                               f"{_trunc(lead.get('title',''),65)}")
        return "\n".join(lines)

    def device_list(self, devices: List[Dict], json_mode: bool = False) -> str:
        if json_mode:
            return json.dumps(devices, indent=2, default=str)
        if not devices:
            return C.dim("  No devices found.")
        rows = [[d.get("device_id",""), d.get("device_type",""),
                  _trunc(d.get("device_model","") or "(unknown)", 30),
                  _trunc(d.get("device_os","") or "(unknown)", 25)]
                 for d in devices]
        return _fmt_table(["Device ID","Type","Model","OS"], rows,
                           [30, 10, 30, 25])

    def relationships(self, rels: List[Dict], json_mode: bool = False) -> str:
        if json_mode:
            return json.dumps(rels, indent=2, default=str)
        if not rels:
            return C.dim("  No relationships found.")
        lines = [C.bold(f"\n  DEVICE RELATIONSHIPS  ({len(rels)})"), _sep()]
        for rel in rels:
            lines.append(
                f"  {C.cyan(_trunc(rel.get('device_a',''),26)):<28} ↔  "
                f"{C.cyan(_trunc(rel.get('device_b',''),26)):<28} "
                f"{C.strength(rel.get('strength','')):<14}  "
                f"{rel.get('confidence_score',0):.2f}  "
                f"({rel.get('evidence_count',0)} entity/entities)")
            types = rel.get("relationship_types",[])
            if types:
                lines.append(f"  {C.dim('  Types: ' + ', '.join(types[:5]))}")
        return "\n".join(lines)

    def leads(self, leads: List[Dict], json_mode: bool = False) -> str:
        if json_mode:
            return json.dumps(leads, indent=2, default=str)
        if not leads:
            return C.dim("  No leads found.")
        lines = [C.bold(f"\n  INVESTIGATIVE LEADS  ({len(leads)})"), _sep()]
        for i, lead in enumerate(leads, 1):
            pri  = lead.get("priority","")
            conf = lead.get("confidence", 0.0)
            devs = lead.get("devices",[])
            lines.append(
                f"  {C.bold(str(i).rjust(3))}. [{C.priority(pri)}]  "
                f"{C.bold(_trunc(lead.get('title',''),60))}")
            lines.append(f"       {_trunc(lead.get('description',''),70)}")
            lines.append(
                f"       Confidence: {conf:.2f}  "
                f"Devices: {', '.join(_trunc(d,20) for d in devs[:4])}"
                + (" …" if len(devs) > 4 else ""))
            ents = lead.get("entities",[])
            if ents:
                ev = ents[0]
                lines.append(f"       Entity: {ev.get('type','')} = "
                               f"{C.cyan(_trunc(str(ev.get('value','')),40))}")
            lines.append("")
        return "\n".join(lines)

    def clusters(self, clusters: List[Dict], json_mode: bool = False) -> str:
        if json_mode:
            return json.dumps(clusters, indent=2, default=str)
        if not clusters:
            return C.dim("  No clusters found.")
        lines = [C.bold(f"\n  DEVICE CLUSTERS  ({len(clusters)})"), _sep()]
        for cl in clusters:
            lines.append(
                f"  {C.bold(cl.get('cluster_id',''))}")
            lines.append(
                f"    Type     : {C.yellow(cl.get('cluster_type',''))}")
            lines.append(
                f"    Devices  : {cl.get('device_count',0)}  →  "
                f"{', '.join(C.cyan(d) for d in cl.get('devices',[])[:5])}"
                + (" …" if len(cl.get('devices',[])) > 5 else ""))
            lines.append(
                f"    Cohesion : {cl.get('cohesion_score',0):.2f}  "
                f"Int. rels: {cl.get('internal_relationships',0)}")
            dom = cl.get("dominant_entities",[])
            if dom:
                lines.append(
                    f"    Dominant : "
                    f"{', '.join(f'{e[\"type\"]}×{e[\"count\"]}' for e in dom[:4])}")
            lines.append("")
        return "\n".join(lines)

    def comparison(self, c: DeviceComparison, json_mode: bool = False) -> str:
        if json_mode:
            return json.dumps(asdict(c), indent=2, default=str)
        lines = [C.bold(f"\n  DEVICE COMPARISON")]
        lines.append(f"  A: {C.cyan(c.device_a)}")
        lines.append(f"  B: {C.cyan(c.device_b)}")
        lines.append(_sep())
        lines.append(
            f"  Verdict     : {C.strength(c.verdict)}  "
            f"Confidence: {c.confidence_score:.2f}")
        lines.append(f"  Shared      : {C.bold(str(len(c.shared_entities)))} entities")
        lines.append(f"  Unique to A : {len(c.unique_to_a)} entities")
        lines.append(f"  Unique to B : {len(c.unique_to_b)} entities")
        lines.append(f"  Timeline overlaps: {len(c.timeline_overlaps)}")
        if c.shared_entities:
            lines.append(f"\n  {C.bold('SHARED ENTITIES')}  ({len(c.shared_entities)})")
            for e in c.shared_entities[:15]:
                lines.append(f"    [{e.get('type','')}]  {C.cyan(e.get('value',''))}")
        if c.timeline_overlaps:
            lines.append(f"\n  {C.bold('SYNCHRONISED EVENTS')}  "
                          f"({len(c.timeline_overlaps)})")
            for ov in c.timeline_overlaps[:5]:
                ea, eb = ov.get("event_a",{}), ov.get("event_b",{})
                lines.append(
                    f"    Δ{ov.get('delta_seconds',0):.0f}s  "
                    f"A:{_trunc(ea.get('description',''),30)}  "
                    f"B:{_trunc(eb.get('description',''),30)}")
        return "\n".join(lines)

    def pivot(self, p: PivotResult, json_mode: bool = False) -> str:
        if json_mode:
            return json.dumps(asdict(p), indent=2, default=str)
        lines = [C.bold(f"\n  ENTITY PIVOT  —  {C.cyan(p.seed_entity_value)}")]
        lines.append(f"  Type   : {p.seed_entity_type}")
        lines.append(f"  Depth  : {p.pivot_depth}")
        lines.append(_sep())
        lines.append(f"  {C.bold('DIRECT DEVICES')}  ({len(p.direct_devices)})")
        for d in p.direct_devices:
            lines.append(f"    → {C.cyan(d)}")
        if p.second_degree:
            lines.append(f"\n  {C.bold('2ND-DEGREE DEVICES')}  "
                          f"({len(p.second_degree)})")
            for d in p.second_degree[:10]:
                lines.append(f"    ··→ {C.dim(d)}")
        if p.connected_entities:
            lines.append(f"\n  {C.bold('CONNECTED ENTITIES')}  "
                          f"({len(p.connected_entities)} shared)")
            rows = [[e.get("entity_type",""),
                     _trunc(e.get("entity_value",""),40),
                     e.get("device_count",0)]
                     for e in p.connected_entities[:12]]
            lines.append(_fmt_table(["Type","Value","Devices"], rows, [18,40,7]))
        return "\n".join(lines)

    def timeline(self, events: List[Dict], device_id: str,
                  json_mode: bool = False) -> str:
        if json_mode:
            return json.dumps(events, indent=2, default=str)
        if not events:
            return C.dim(f"  No timeline events for {device_id}.")
        lines = [C.bold(f"\n  TIMELINE  —  {C.cyan(device_id)}  "
                          f"({len(events)} events)"), _sep()]
        for ev in events:
            ts    = ev.get("timestamp_utc","")[:16].replace("T"," ")
            etype = C.cyan(_trunc(ev.get("event_type",""),22))
            desc  = _trunc(ev.get("description",""),50)
            actor = ev.get("actor","")
            lines.append(f"  {C.dim(ts)}  {etype:<28}  {desc}"
                          + (f"  [{C.dim(actor)}]" if actor else ""))
        return "\n".join(lines)

    def stats(self, s: CaseStats, json_mode: bool = False) -> str:
        if json_mode:
            return json.dumps(asdict(s), indent=2, default=str)
        lines = [C.bold(f"\n  CASE STATISTICS  —  {C.cyan(s.case_id)}"), _sep()]
        stats_rows = [
            ["Devices",           s.devices],
            ["Parsed Artifacts",  s.artifacts],
            ["Extracted Entities",s.entities],
            ["Timeline Events",   s.timeline_events],
            ["Relationships",     s.relationships],
            ["Clusters",          s.clusters],
        ]
        for label, val in stats_rows:
            lines.append(f"  {label:<26}  {C.bold(str(val))}")
        lines.append(_sep("─", 40))
        entity_rows = [
            ["Phone Numbers",     s.unique_phones],
            ["Email Addresses",   s.unique_emails],
            ["IP Addresses",      s.unique_ips],
            ["Domains",           s.unique_domains],
            ["Crypto Wallets",    s.unique_crypto],
        ]
        for label, val in entity_rows:
            lines.append(f"  {label:<26}  {val}")
        lines.append(_sep("─", 40))
        lead_rows = [
            [C.red("HIGH"),    s.leads_high],
            [C.yellow("MEDIUM"), s.leads_medium],
            [C.green("LOW"),   s.leads_low],
        ]
        lines.append(f"  {'Investigative Leads':<26}  "
                      f"H:{s.leads_high}  M:{s.leads_medium}  L:{s.leads_low}")
        if s.parse_errors:
            lines.append(f"  {C.yellow('Parse Errors'):<35}  {s.parse_errors}")
        return "\n".join(lines)

    def infra(self, links: List[Dict], entity: str,
               json_mode: bool = False) -> str:
        if json_mode:
            return json.dumps(links, indent=2, default=str)
        if not links:
            return C.dim(f"  No infrastructure links for: {entity}")
        lines = [C.bold(f"\n  INFRASTRUCTURE  —  {C.cyan(entity)}"), _sep()]
        for lnk in links:
            lines.append(
                f"  {_trunc(lnk.get('entity_a_val',''),35):<37} "
                f"→[{C.yellow(lnk.get('link_type','')):<25}]→  "
                f"{C.cyan(_trunc(lnk.get('entity_b_val',''),35))}")
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Report Generator
# ─────────────────────────────────────────────────────────────────────────────

class ReportGenerator:
    """Produces formal Markdown investigation reports."""

    def __init__(self, engine: QueryEngine, case_id: str):
        self.engine  = engine
        self.case_id = case_id

    def _header(self, title: str) -> str:
        return (f"# HIVE Investigation Report\n"
                f"## {title}\n"
                f"**Case ID:** `{self.case_id}`  \n"
                f"**Generated:** {_utcnow()}  \n"
                f"**Tool:** HIVE-investigator v{HIVE_INV_VERSION}\n\n"
                f"---\n")

    def summary(self) -> str:
        stats   = self.engine.stats()
        devices = self.engine.list_devices()
        leads   = self.engine.leads()
        clusters= self.engine.clusters()

        lines = [self._header(f"Case Summary — {self.case_id}")]

        lines.append("## Executive Summary\n")
        lines.append(f"| Metric | Value |")
        lines.append(f"|--------|-------|")
        for label, val in [
            ("Devices Seized",       stats.devices),
            ("Artifacts Parsed",     stats.artifacts),
            ("Entities Extracted",   stats.entities),
            ("Timeline Events",      stats.timeline_events),
            ("Relationships Found",  stats.relationships),
            ("Clusters Detected",    stats.clusters),
            ("HIGH Priority Leads",  stats.leads_high),
            ("MEDIUM Priority Leads",stats.leads_medium),
        ]:
            lines.append(f"| {label} | **{val}** |")
        lines.append("")

        # Entity breakdown
        lines.append("## Entity Intelligence Summary\n")
        lines.append("| Entity Type | Unique Values |")
        lines.append("|-------------|---------------|")
        for label, val in [
            ("Phone Numbers",    stats.unique_phones),
            ("Email Addresses",  stats.unique_emails),
            ("IP Addresses",     stats.unique_ips),
            ("Domains",          stats.unique_domains),
            ("Crypto Wallets",   stats.unique_crypto),
        ]:
            lines.append(f"| {label} | {val} |")
        lines.append("")

        # Device inventory
        lines.append("## Device Inventory\n")
        lines.append("| Device ID | Type | Model | OS |")
        lines.append("|-----------|------|-------|----|")
        for d in devices:
            lines.append(
                f"| `{d.get('device_id','')}` | {d.get('device_type','')} "
                f"| {d.get('device_model','(unknown)')} "
                f"| {d.get('device_os','(unknown)')} |")
        lines.append("")

        # Clusters
        if clusters:
            lines.append("## Detected Clusters\n")
            for cl in clusters:
                lines.append(f"### {cl.get('cluster_id','')}"
                               f" — {cl.get('cluster_type','')}\n")
                lines.append(f"- **Devices:** {cl.get('device_count',0)}")
                lines.append(f"- **Cohesion:** {cl.get('cohesion_score',0):.2f}")
                lines.append(f"- **Members:** "
                               f"{', '.join(f'`{d}`' for d in cl.get('devices',[])[:8])}")
                dom = cl.get("dominant_entities",[])
                if dom:
                    lines.append(f"- **Dominant entity types:** "
                                   f"{', '.join(e['type'] for e in dom[:5])}")
                lines.append("")

        # Leads
        if leads:
            lines.append("## Investigative Leads\n")
            for pri in ("HIGH", "MEDIUM", "LOW"):
                pri_leads = [l for l in leads if l.get("priority") == pri]
                if not pri_leads:
                    continue
                lines.append(f"### {pri} Priority\n")
                for lead in pri_leads:
                    lines.append(f"**{lead.get('title','')}**  ")
                    lines.append(f"{lead.get('description','')}  ")
                    lines.append(
                        f"*Confidence: {lead.get('confidence',0):.2f} | "
                        f"Devices: {', '.join(f'`{d}`' for d in lead.get('devices',[])[:4])}*\n")

        return "\n".join(lines)

    def device_report(self, device_id: str) -> str:
        profile = self.engine.device_profile(device_id)
        if not profile:
            return f"# Device Not Found\n\nDevice `{device_id}` not in case `{self.case_id}`."

        lines = [self._header(f"Device Report — {device_id}")]
        lines.append("## Device Information\n")
        for label, val in [
            ("Device ID",    profile.device_id),
            ("Type",         profile.device_type),
            ("Model",        profile.device_model or "(unknown)"),
            ("OS",           profile.device_os or "(unknown)"),
            ("Acquisition",  profile.acquisition_id),
            ("Clusters",     ", ".join(profile.cluster_ids) or "None"),
        ]:
            lines.append(f"**{label}:** {val}  ")
        lines.append("")

        if profile.entity_counts:
            lines.append("## Entity Inventory\n")
            lines.append("| Entity Type | Unique Values |")
            lines.append("|-------------|---------------|")
            for etype, cnt in sorted(profile.entity_counts.items(),
                                      key=lambda x: x[1], reverse=True):
                lines.append(f"| {etype} | {cnt} |")
            lines.append("")

        if profile.top_entities:
            lines.append("## Top Entities\n")
            lines.append("| Type | Value | Occurrences |")
            lines.append("|------|-------|-------------|")
            for e in profile.top_entities[:20]:
                lines.append(
                    f"| {e.get('entity_type','')} "
                    f"| `{e.get('entity_value','')[:50]}` "
                    f"| {e.get('occurrences',1)} |")
            lines.append("")

        if profile.relationships:
            lines.append("## Relationships\n")
            lines.append("| Peer Device | Strength | Score | Evidence |")
            lines.append("|-------------|----------|-------|----------|")
            for rel in profile.relationships[:15]:
                peer = (rel.get("device_b") if rel.get("device_a") == device_id
                         else rel.get("device_a"))
                lines.append(
                    f"| `{peer}` | {rel.get('strength','')} "
                    f"| {rel.get('confidence_score',0):.2f} "
                    f"| {rel.get('evidence_count',0)} |")
            lines.append("")

        tl = profile.timeline_summary
        if tl.get("total"):
            lines.append("## Timeline Summary\n")
            lines.append(
                f"**Period:** {tl.get('earliest','')[:10]} → "
                f"{tl.get('latest','')[:10]}  ")
            lines.append(f"**Total events:** {tl.get('total',0)}\n")
            lines.append("| Event Type | Count |")
            lines.append("|------------|-------|")
            for etype, cnt in sorted(tl.get("by_type",{}).items(),
                                      key=lambda x: x[1], reverse=True):
                lines.append(f"| {etype} | {cnt} |")
            lines.append("")

        if profile.leads:
            lines.append("## Investigative Leads\n")
            for lead in profile.leads:
                lines.append(
                    f"- **[{lead.get('priority','')}]** {lead.get('title','')}  \n"
                    f"  {lead.get('description','')[:200]}\n")

        return "\n".join(lines)

    def leads_report(self) -> str:
        leads   = self.engine.leads()
        lines   = [self._header("Investigative Leads Report")]
        lines.append(f"**Total leads:** {len(leads)}\n")
        for pri in ("HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
            pri_leads = [l for l in leads if l.get("priority") == pri]
            if not pri_leads:
                continue
            lines.append(f"## {pri} Priority  ({len(pri_leads)} leads)\n")
            for i, lead in enumerate(pri_leads, 1):
                lines.append(f"### {i}. {lead.get('title','')}\n")
                lines.append(f"**Type:** {lead.get('lead_type','')}  ")
                lines.append(f"**Confidence:** {lead.get('confidence',0):.2f}  ")
                lines.append(
                    f"**Devices:** {', '.join(f'`{d}`' for d in lead.get('devices',[]))}\n")
                lines.append(f"{lead.get('description','')}\n")
                ents = lead.get("entities",[])
                if ents:
                    for e in ents[:3]:
                        if isinstance(e, dict):
                            lines.append(f"- `{e.get('type','')}` = "
                                           f"`{str(e.get('value', e.get('count','')))}`")
                lines.append("")
        return "\n".join(lines)

    def full_report(self) -> str:
        parts = [
            self.summary(),
            "\n---\n# Full Device Profiles\n",
        ]
        devices = self.engine.list_devices()
        for dev in devices:
            parts.append(self.device_report(dev.get("device_id","")))
        parts.append("\n---\n# Leads Detail\n")
        parts.append(self.leads_report())
        return "\n".join(parts)


# ─────────────────────────────────────────────────────────────────────────────
# Interactive Shell
# ─────────────────────────────────────────────────────────────────────────────

class HIVEShell(cmd.Cmd):
    intro    = ""
    prompt   = C.bold(C.cyan("HIVE")) + C.dim("> ") if C.cyan.__func__(C, "") != "" else "HIVE> "

    def __init__(self, engine: QueryEngine, fmt: Formatter,
                  report_gen: ReportGenerator,
                  case_id: str, json_mode: bool = False):
        super().__init__()
        self.engine     = engine
        self.fmt        = fmt
        self.rgen       = report_gen
        self.case_id    = case_id
        self.json_mode  = json_mode
        self._load_history()

    def _load_history(self) -> None:
        try:
            readline.read_history_file(HISTORY_FILE)
            readline.set_history_length(1000)
        except Exception:
            pass

    def _save_history(self) -> None:
        try:
            readline.write_history_file(HISTORY_FILE)
        except Exception:
            pass

    def _out(self, text: str) -> None:
        _print(text)

    def _parse(self, line: str) -> List[str]:
        try:
            return shlex.split(line)
        except ValueError:
            return line.split()

    def _arg(self, args: List[str], flag: str,
              default: str = "") -> str:
        try:
            i = args.index(flag)
            return args[i + 1] if i + 1 < len(args) else default
        except ValueError:
            return default

    def _has_flag(self, args: List[str], flag: str) -> bool:
        return flag in args

    def _positional(self, args: List[str]) -> List[str]:
        """Return args that are not flag keys or flag values."""
        skip_next = False
        result = []
        for a in args:
            if skip_next:
                skip_next = False
                continue
            if a.startswith("--"):
                skip_next = True
                continue
            result.append(a)
        return result

    # ── Commands ──────────────────────────────────────────────

    def do_search(self, line: str) -> None:
        """search <value>  —  Search any entity value across all devices."""
        line = line.strip()
        if not line:
            _print(C.yellow("  Usage: search <value>"))
            return
        result = self.engine.search(line)
        self._out(self.fmt.search_result(result, self.json_mode))

    def do_pivot(self, line: str) -> None:
        """pivot <value>  —  Expand an entity to its full device network."""
        line = line.strip()
        if not line:
            _print(C.yellow("  Usage: pivot <value>"))
            return
        result = self.engine.pivot(line)
        self._out(self.fmt.pivot(result, self.json_mode))

    def do_infra(self, line: str) -> None:
        """infra <entity>  —  Trace infrastructure links for a domain/IP/email."""
        line = line.strip()
        if not line:
            _print(C.yellow("  Usage: infra <domain|ip|email>"))
            return
        links = self.engine.infra(line)
        self._out(self.fmt.infra(links, line, self.json_mode))

    def do_devices(self, _: str) -> None:
        """devices  —  List all devices in this case."""
        devs = self.engine.list_devices()
        self._out(self.fmt.device_list(devs, self.json_mode))

    def do_device(self, line: str) -> None:
        """device <id>  —  Full profile of a specific device."""
        device_id = line.strip()
        if not device_id:
            _print(C.yellow("  Usage: device <device_id>"))
            return
        profile = self.engine.device_profile(device_id)
        if profile is None:
            _print(C.red(f"  Device not found: {device_id}"))
            return
        self._out(self.fmt.device_profile(profile, self.json_mode))

    def do_compare(self, line: str) -> None:
        """compare <id_a> <id_b>  —  Side-by-side device comparison."""
        args = self._parse(line)
        pos  = self._positional(args)
        if len(pos) < 2:
            _print(C.yellow("  Usage: compare <device_a_id> <device_b_id>"))
            return
        cmp = self.engine.compare(pos[0], pos[1])
        self._out(self.fmt.comparison(cmp, self.json_mode))

    def do_timeline(self, line: str) -> None:
        """timeline <id> [--from DATE] [--to DATE]  —  Device timeline."""
        args      = self._parse(line)
        pos       = self._positional(args)
        if not pos:
            _print(C.yellow("  Usage: timeline <device_id> [--from YYYY-MM-DD] [--to YYYY-MM-DD]"))
            return
        device_id = pos[0]
        from_ts   = self._arg(args, "--from")
        to_ts     = self._arg(args, "--to")
        events    = self.engine.timeline(device_id, from_ts=from_ts, to_ts=to_ts)
        self._out(self.fmt.timeline(events, device_id, self.json_mode))

    def do_relationships(self, line: str) -> None:
        """relationships [--device <id>] [--min-score N]  —  View relationships."""
        args      = self._parse(line)
        device_id = self._arg(args, "--device")
        min_score = float(self._arg(args, "--min-score", "0.0"))
        rels      = self.engine.relationships(device_id or None, min_score)
        self._out(self.fmt.relationships(rels, self.json_mode))

    def do_clusters(self, _: str) -> None:
        """clusters  —  List all detected device clusters."""
        clusters = self.engine.clusters()
        self._out(self.fmt.clusters(clusters, self.json_mode))

    def do_cluster(self, line: str) -> None:
        """cluster <id>  —  Deep-dive into a specific cluster."""
        cluster_id = line.strip()
        if not cluster_id:
            _print(C.yellow("  Usage: cluster <cluster_id>"))
            return
        cl = self.engine.cluster(cluster_id)
        if not cl:
            _print(C.red(f"  Cluster not found: {cluster_id}"))
            return
        if self.json_mode:
            _print(json.dumps(cl, indent=2, default=str))
            return
        self._out(self.fmt.clusters([cl]))
        # Also show relationships within cluster
        devices = cl.get("devices", [])
        if len(devices) > 1:
            _print(C.bold(f"\n  INTRA-CLUSTER RELATIONSHIPS"))
            rels = [r for r in self.engine.relationships()
                     if r.get("device_a") in devices and r.get("device_b") in devices]
            self._out(self.fmt.relationships(rels))

    def do_leads(self, line: str) -> None:
        """leads [--priority HIGH|MEDIUM|LOW|ALL]  —  View investigative leads."""
        args     = self._parse(line)
        priority = self._arg(args, "--priority", "ALL")
        leads    = self.engine.leads(priority if priority != "ALL" else "")
        self._out(self.fmt.leads(leads, self.json_mode))

    def do_stats(self, _: str) -> None:
        """stats  —  Case statistics dashboard."""
        s = self.engine.stats()
        self._out(self.fmt.stats(s, self.json_mode))

    def do_report(self, line: str) -> None:
        """report <summary|full|device|cluster|leads> [<id>] [--output FILE]"""
        args    = self._parse(line)
        pos     = self._positional(args)
        outfile = self._arg(args, "--output")

        if not pos:
            _print(C.yellow("  Usage: report <summary|full|device <id>|leads> [--output FILE]"))
            return

        rtype = pos[0].lower()
        if rtype == "summary":
            content = self.rgen.summary()
        elif rtype == "full":
            content = self.rgen.full_report()
        elif rtype == "device":
            if len(pos) < 2:
                _print(C.yellow("  Usage: report device <device_id>"))
                return
            content = self.rgen.device_report(pos[1])
        elif rtype == "leads":
            content = self.rgen.leads_report()
        elif rtype == "cluster":
            if len(pos) < 2:
                _print(C.yellow("  Usage: report cluster <cluster_id>"))
                return
            cl = self.engine.cluster(pos[1])
            if not cl:
                _print(C.red(f"  Cluster not found: {pos[1]}"))
                return
            content = self.rgen.device_report.__doc__ or json.dumps(cl, indent=2)
        else:
            _print(C.yellow(f"  Unknown report type: {rtype}"))
            return

        if outfile:
            with open(outfile, "w", encoding="utf-8") as fh:
                fh.write(content)
            _print(C.green(f"  Report written → {outfile}"))
        else:
            _print(content)

    def do_help(self, _: str) -> None:
        """help  —  Show command reference."""
        _print(HELP_TEXT)

    def do_exit(self, _: str) -> bool:
        """exit  —  Quit HIVE Investigator."""
        self._save_history()
        _print(C.dim("\n  Session ended. Goodbye.\n"))
        return True

    def do_quit(self, line: str) -> bool:
        """quit  —  Quit HIVE Investigator."""
        return self.do_exit(line)

    def do_EOF(self, _: str) -> bool:
        _print()
        return self.do_exit("")

    def default(self, line: str) -> None:
        _print(C.yellow(f"  Unknown command: '{line.split()[0]}'  "
                          "(type 'help' for commands)"))

    def emptyline(self) -> None:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# HIVE Investigator — Orchestrator
# ─────────────────────────────────────────────────────────────────────────────

class HIVEInvestigator:
    """
    Top-level orchestrator.  Assembles adapters, engine, formatter, and
    report generator; then routes to interactive shell, single-query, or
    report-generation mode.
    """

    def __init__(self, db_path: str, case_id: str,
                  mongo_uri:  str  = DEFAULT_MONGO_URI,
                  mongo_db:   str  = DEFAULT_MONGO_DB,
                  use_mongo:  bool = True,
                  json_mode:  bool = False,
                  no_color:   bool = False):
        if no_color:
            C.no_color()

        self.sqlite = SQLiteAdapter(db_path)

        # Attempt MongoDB connection
        self.mongo: Optional[MongoAdapter] = None
        if use_mongo and HAS_MONGO:
            try:
                self.mongo = MongoAdapter(mongo_uri, mongo_db)
            except Exception as exc:
                logging.getLogger("hive.investigator").warning(
                    f"MongoDB unavailable ({exc}); running SQLite-only mode")

        # Auto-detect case_id if needed
        if not case_id:
            ids = self.sqlite.all_case_ids()
            case_id = ids[0] if ids else "UNKNOWN"

        self.case_id   = case_id
        self.json_mode = json_mode
        self.engine    = QueryEngine(self.sqlite, self.mongo, case_id)
        self.fmt       = Formatter()
        self.rgen      = ReportGenerator(self.engine, case_id)

    def interactive(self) -> None:
        _print(BANNER.format(v=HIVE_INV_VERSION))
        _print(C.bold(f"  Case    : {C.cyan(self.case_id)}"))
        _print(C.dim(f"  SQLite  : {self.sqlite.conn}"))
        _print(C.dim(f"  MongoDB : {'connected' if self.mongo else 'unavailable (SQLite-only mode)'}"))
        _print(C.dim(  "  Type 'help' for commands  |  'exit' to quit\n"))

        shell = HIVEShell(self.engine, self.fmt, self.rgen,
                           self.case_id, self.json_mode)
        try:
            shell.cmdloop()
        except KeyboardInterrupt:
            shell.do_exit("")

    def query(self, command: str) -> str:
        """Run a single command string and return the formatted output."""
        shell  = HIVEShell(self.engine, self.fmt, self.rgen,
                            self.case_id, self.json_mode)
        parts  = command.strip().split(None, 1)
        cmd_   = parts[0].lower() if parts else ""
        rest   = parts[1] if len(parts) > 1 else ""
        fn     = getattr(shell, f"do_{cmd_}", None)
        if fn is None:
            return f"Unknown command: {cmd_}"

        # Capture output by temporarily replacing stdout
        import io
        buf = io.StringIO()
        old = sys.stdout
        sys.stdout = buf
        try:
            fn(rest)
        finally:
            sys.stdout = old
        return buf.getvalue()

    def report(self, rtype: str, target: str = "") -> str:
        """Generate and return a Markdown report."""
        if rtype == "summary":
            return self.rgen.summary()
        if rtype == "full":
            return self.rgen.full_report()
        if rtype == "device":
            return self.rgen.device_report(target)
        if rtype == "leads":
            return self.rgen.leads_report()
        return f"Unknown report type: {rtype}"

    def batch(self, commands_file: str) -> None:
        """Execute commands from a file, one per line."""
        with open(commands_file, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                _print(C.bold(C.dim(f"\nHIVE> {line}")))
                _print(self.query(line))

    def close(self) -> None:
        self.sqlite.close()
        if self.mongo:
            self.mongo.close()


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def build_cli() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="investigator.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "HIVE Platform  —  Stage 4: Investigation Query Engine  v"
            + HIVE_INV_VERSION + "\n"
            "Primary interface for searching, exploring, and reporting on\n"
            "intelligence generated by the HIVE pipeline."
        ),
        epilog="""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 QUICK-START EXAMPLES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Launch interactive shell:
  python3 investigator.py --db /evidence/CASE-001/hive_evidence.db --case-id CASE-001

Single search query:
  python3 investigator.py --db /evidence/CASE-001/hive_evidence.db \\
    --case-id CASE-001 --query "search +447911123456"

JSON output for dashboards:
  python3 investigator.py --db /evidence/CASE-001/hive_evidence.db \\
    --case-id CASE-001 --json --query "leads --priority HIGH"

Generate a summary report:
  python3 investigator.py --db /evidence/CASE-001/hive_evidence.db \\
    --case-id CASE-001 --report summary --output /evidence/CASE-001/report.md

Generate a full case report:
  python3 investigator.py --db /evidence/CASE-001/hive_evidence.db \\
    --case-id CASE-001 --report full --output /evidence/CASE-001/full_report.md

Generate a device report:
  python3 investigator.py --db /evidence/CASE-001/hive_evidence.db \\
    --case-id CASE-001 --report device --target android_ABC123_a1b2 \\
    --output /evidence/CASE-001/device_report.md

Batch mode:
  python3 investigator.py --db /evidence/CASE-001/hive_evidence.db \\
    --case-id CASE-001 --batch queries.txt

SQLite-only (no MongoDB):
  python3 investigator.py --db /evidence/CASE-001/hive_evidence.db \\
    --case-id CASE-001 --no-mongo
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
    )
    g = p.add_argument_group("Input")
    g.add_argument("--db",       required=True, metavar="SQLITE_DB",
                    help="Path to hive_evidence.db from parser.py")
    g.add_argument("--case-id",  metavar="ID", default="",
                    help="Case identifier (auto-detected if omitted)")

    g2 = p.add_argument_group("MongoDB")
    g2.add_argument("--mongo-uri", default=DEFAULT_MONGO_URI,
                     help=f"MongoDB URI (default: {DEFAULT_MONGO_URI})")
    g2.add_argument("--mongo-db",  default=DEFAULT_MONGO_DB,
                     help=f"MongoDB database (default: {DEFAULT_MONGO_DB})")
    g2.add_argument("--no-mongo",  action="store_true",
                     help="SQLite-only mode (skip MongoDB)")

    g3 = p.add_argument_group("Execution Mode")
    g3.add_argument("--query",  metavar="COMMAND",
                     help="Execute a single shell command and exit")
    g3.add_argument("--batch",  metavar="FILE",
                     help="Execute commands from a file (one per line)")
    g3.add_argument("--report", metavar="TYPE",
                     choices=["summary","full","device","leads","cluster"],
                     help="Generate a report (summary|full|device|leads|cluster)")
    g3.add_argument("--target", metavar="ID",
                     help="Target device/cluster ID for --report device/cluster")
    g3.add_argument("--output", metavar="FILE",
                     help="Write report to file instead of stdout")

    g4 = p.add_argument_group("Output")
    g4.add_argument("--json",     action="store_true",
                     help="Output results as JSON (pipe-friendly)")
    g4.add_argument("--no-color", action="store_true",
                     help="Disable ANSI color output")
    g4.add_argument("-v","--verbose", action="store_true",
                     help="Debug logging")
    return p


def main() -> int:
    cli  = build_cli()
    args = cli.parse_args()

    logging.basicConfig(
        level   = logging.DEBUG if args.verbose else logging.WARNING,
        format  = "[%(levelname)s] %(name)s — %(message)s")

    try:
        inv = HIVEInvestigator(
            db_path   = args.db,
            case_id   = args.case_id,
            mongo_uri = args.mongo_uri,
            mongo_db  = args.mongo_db,
            use_mongo = not args.no_mongo,
            json_mode = args.json,
            no_color  = args.no_color,
        )
    except FileNotFoundError as exc:
        print(f"[!] {exc}")
        return 1

    try:
        # Report generation mode
        if args.report:
            content = inv.report(args.report, args.target or "")
            if args.output:
                with open(args.output, "w", encoding="utf-8") as fh:
                    fh.write(content)
                print(f"Report written → {args.output}")
            else:
                print(content)

        # Batch mode
        elif args.batch:
            if not os.path.exists(args.batch):
                print(f"[!] Batch file not found: {args.batch}")
                return 1
            inv.batch(args.batch)

        # Single-query mode
        elif args.query:
            output = inv.query(args.query)
            if args.output:
                with open(args.output, "w", encoding="utf-8") as fh:
                    fh.write(output)
            else:
                print(output)

        # Interactive shell (default)
        else:
            inv.interactive()

    finally:
        inv.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
