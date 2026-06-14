#!/usr/bin/env python3
"""
correlator.py  —  HIVE Platform · Stage 3: Intelligence Correlation Engine
═══════════════════════════════════════════════════════════════════════════════
High-scale Investigation and Verification Engine  (HIVE)  v1.0.0

Ingests the structured evidence database produced by parser.py and discovers
relationships, clusters, and investigative leads across all seized devices.

Core capabilities
  • Cross-device entity correlation (phones, emails, IPs, wallets, usernames …)
  • Weighted confidence scoring with diminishing-returns aggregation
  • Device-to-device relationship graph construction
  • Graph cluster detection (connected components → Louvain if networkx available)
  • Cluster-type inference (fraud network, phishing infra, botnet, comms network …)
  • Timeline synchronisation analysis (co-ordinated activity windows)
  • Investigative lead generation with priority scoring
  • Infrastructure graph (IP ↔ domain ↔ URL ↔ package relationships)

Storage backends
  Primary : MongoDB (pymongo required)  pip install pymongo
  Fallback : JSON files  (used automatically when MongoDB is unavailable)

Optional enhancements
  networkx  (pip install networkx)  — Louvain community detection

Pipeline position
  collector.py → parser.py → [correlator.py] → visualiser.py / investigator.py

MongoDB collections  (database: hive)
  devices              — device profiles from manifests
  entity_network       — entities and the devices they appear on
  device_relationships — device-to-device relationship records
  device_clusters      — cluster memberships and characterisation
  timeline_correlations— synchronised event pairs
  investigative_leads  — prioritised actionable findings
  infrastructure_graph — entity-to-entity infrastructure links
  correlation_runs     — audit log of every correlator execution

Usage:
  python3 correlator.py --db /evidence/CASE-001/hive_evidence.db --case-id CASE-001
  python3 correlator.py --db /evidence/CASE-001/hive_evidence.db --case-id CASE-001 --mongo-uri mongodb://localhost:27017
  python3 correlator.py --db /evidence/CASE-001/hive_evidence.db --case-id CASE-001 --no-mongo
  python3 correlator.py --db /evidence/CASE-001/hive_evidence.db --case-id CASE-001 --sync-window 60
═══════════════════════════════════════════════════════════════════════════════
"""

from __future__ import annotations

import os
import re
import sys
import json
import uuid
import math
import sqlite3
import logging
import argparse
import datetime
import itertools
import threading
import collections
import concurrent.futures
from abc         import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from typing      import Optional, List, Dict, Set, Any, Tuple, DefaultDict

# ── Optional: pymongo ─────────────────────────────────────────────────────────
try:
    import pymongo                               # pip install pymongo
    import pymongo.errors
    HAS_MONGO = True
except ImportError:
    HAS_MONGO = False

# ── Optional: networkx ────────────────────────────────────────────────────────
try:
    import networkx as nx                        # pip install networkx
    HAS_NX = True
except ImportError:
    HAS_NX = False

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

HIVE_CORRELATOR_VERSION = "1.0.0"
HIVE_TOOL               = "HIVE-correlator"
LOG_FMT                 = "[%(asctime)s] %(levelname)-8s %(name)s — %(message)s"
DATE_FMT                = "%Y-%m-%dT%H:%M:%SZ"
DEFAULT_MONGO_URI       = "mongodb://localhost:27017"
DEFAULT_MONGO_DB        = "hive"
DEFAULT_SYNC_WINDOW_MIN = 30        # minutes – timeline co-occurrence window
DEFAULT_MIN_CONFIDENCE  = 0.25      # discard device pairs below this score
DEFAULT_WORKERS         = 4

# ─────────────────────────────────────────────────────────────────────────────
# Entity Confidence Weights
# ─────────────────────────────────────────────────────────────────────────────
# Weights reflect how unique / significant sharing this entity type is.
# A shared BTC wallet is near-certain attribution; a shared public IP may be NAT.

ENTITY_WEIGHTS: Dict[str, float] = {
    "CRYPTO_BTC":    1.00,   # unique per actor; sharing = strong link
    "CRYPTO_ETH":    1.00,
    "IMEI":          1.00,   # globally unique device identifier
    "HASH_SHA256":   0.95,   # exact file match
    "MAC_ADDRESS":   0.95,   # hardware address (can be spoofed, but rare)
    "PHONE":         0.90,   # highly personal
    "EMAIL":         0.87,
    "ANDROID_ID":    0.87,   # persistent Android installation ID
    "HASH_MD5":      0.80,
    "USERNAME":      0.78,
    "WIFI_SSID":     0.72,   # location / household link
    "HASH_SHA1":     0.75,
    "URL":           0.65,
    "DOMAIN":        0.58,
    "IPV6":          0.60,
    "IPV4":          0.48,   # carrier NAT / shared hosting dilutes this
    "ANDROID_PACKAGE":0.32,  # common apps appear on many devices
    "FILE_PATH":     0.40,
}

# Relationship strength tiers
STRENGTH_TIERS = [
    (0.85, "DEFINITIVE"),
    (0.65, "STRONG"),
    (0.40, "MODERATE"),
    (0.00, "WEAK"),
]

# Lead priority thresholds
LEAD_PRIORITY_HIGH   = 0.80
LEAD_PRIORITY_MEDIUM = 0.55
LEAD_PRIORITY_LOW    = 0.30

# ── Noise / exclusion sets ────────────────────────────────────────────────────

# Public IPs that are infrastructure noise (DNS resolvers, CDN anycast, etc.)
_NOISE_IPS: Set[str] = {
    "8.8.8.8","8.8.4.4","1.1.1.1","1.0.0.1","9.9.9.9","149.112.112.112",
    "208.67.222.222","208.67.220.220","64.6.64.6","64.6.65.6",
    "0.0.0.0","255.255.255.255",
}

# Domains that appear on virtually every device (not investigatively useful)
_NOISE_DOMAINS: Set[str] = {
    "google.com","googleapis.com","gstatic.com","googleusercontent.com",
    "googlevideo.com","google-analytics.com","doubleclick.net",
    "facebook.com","fbcdn.net","fbsbx.com","instagram.com","cdninstagram.com",
    "whatsapp.com","whatsapp.net","telegram.org",
    "apple.com","icloud.com","apple-dns.net","mzstatic.com",
    "microsoft.com","windows.com","live.com","office.com","azure.com",
    "windowsupdate.com","microsoftonline.com",
    "amazon.com","amazonaws.com","cloudfront.net","awsdns.com",
    "cloudflare.com","cloudflare-dns.com","1dot1dot1dot1.cloudflare-dns.com",
    "akamai.net","akamaiedge.net","akamaihd.net",
    "youtube.com","ytimg.com","googlevideo.com",
    "twitter.com","twimg.com","t.co",
    "tiktok.com","tiktokcdn.com",
    "reddit.com","redditmedia.com","redd.it",
}

# Android system / framework packages (ubiquitous; no forensic significance)
_NOISE_PACKAGES_PREFIX: Tuple[str, ...] = (
    "com.android.",
    "com.google.android.",
    "android.",
    "com.samsung.android.app.galaxyfinder",
    "com.sec.android.",
    "com.huawei.systemmanager",
    "com.xiaomi.miui",
    "com.coloros.",
    "com.oppo.",
    "com.vivo.",
)

# Phone numbers to exclude (emergency services etc.)
_NOISE_PHONES: Set[str] = {"911","999","112","110","118","119","000"}

# ─────────────────────────────────────────────────────────────────────────────
# Data Models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SharedEntity:
    """An entity (IOC) that appears on more than one device."""
    entity_type:   str
    entity_value:  str
    devices:       List[str]  = field(default_factory=list)
    artifact_types:List[str]  = field(default_factory=list)
    first_seen:    str        = ""
    last_seen:     str        = ""
    device_count:  int        = 0
    significance:  float      = 0.0


@dataclass
class DeviceRelationship:
    """A weighted link between two devices sharing one or more entities."""
    relationship_id:  str   = field(default_factory=lambda: str(uuid.uuid4()))
    case_id:          str   = ""
    run_id:           str   = ""
    device_a:         str   = ""
    device_b:         str   = ""
    relationship_types: List[str] = field(default_factory=list)
    shared_entities:  List[Dict]  = field(default_factory=list)
    confidence_score: float = 0.0
    strength:         str   = "WEAK"
    evidence_count:   int   = 0
    created_at:       str   = field(default_factory=lambda: _utcnow())


@dataclass
class DeviceCluster:
    """A group of related devices forming a criminal or operational network."""
    cluster_id:         str   = field(default_factory=lambda: f"CLUSTER-{uuid.uuid4().hex[:8].upper()}")
    case_id:            str   = ""
    run_id:             str   = ""
    devices:            List[str]  = field(default_factory=list)
    device_count:       int   = 0
    cluster_type:       str   = "UNKNOWN"
    cohesion_score:     float = 0.0
    dominant_entities:  List[Dict] = field(default_factory=list)
    key_entity_types:   List[str]  = field(default_factory=list)
    internal_relationships: int = 0
    created_at:         str   = field(default_factory=lambda: _utcnow())


@dataclass
class TimelineCorrelation:
    """Two events on different devices that occurred within a sync window."""
    correlation_id: str   = field(default_factory=lambda: str(uuid.uuid4()))
    case_id:        str   = ""
    run_id:         str   = ""
    device_a:       str   = ""
    device_b:       str   = ""
    event_a:        Dict  = field(default_factory=dict)
    event_b:        Dict  = field(default_factory=dict)
    delta_seconds:  float = 0.0
    sync_score:     float = 0.0
    created_at:     str   = field(default_factory=lambda: _utcnow())


@dataclass
class InvestigativeLead:
    """A prioritised finding surfaced from the correlation analysis."""
    lead_id:     str   = field(default_factory=lambda: str(uuid.uuid4()))
    case_id:     str   = ""
    run_id:      str   = ""
    lead_type:   str   = ""
    priority:    str   = "LOW"
    title:       str   = ""
    description: str   = ""
    devices:     List[str]  = field(default_factory=list)
    entities:    List[Dict] = field(default_factory=list)
    confidence:  float = 0.0
    tags:        List[str]  = field(default_factory=list)
    created_at:  str   = field(default_factory=lambda: _utcnow())


@dataclass
class InfrastructureLink:
    """A relationship between two infrastructure entities."""
    link_id:      str   = field(default_factory=lambda: str(uuid.uuid4()))
    case_id:      str   = ""
    run_id:       str   = ""
    entity_a_type:str   = ""
    entity_a_val: str   = ""
    entity_b_type:str   = ""
    entity_b_val: str   = ""
    link_type:    str   = ""     # CO_OCCURRENCE, EMAIL_DOMAIN, URL_DOMAIN …
    devices:      List[str] = field(default_factory=list)
    created_at:   str   = field(default_factory=lambda: _utcnow())


@dataclass
class CorrelationResult:
    """Summary of a full correlation run."""
    run_id:                str   = field(default_factory=lambda: str(uuid.uuid4()))
    case_id:               str   = ""
    evidence_db:           str   = ""
    started_at:            str   = ""
    completed_at:          str   = ""
    devices_analyzed:      int   = 0
    entities_analyzed:     int   = 0
    shared_entities_found: int   = 0
    relationships_found:   int   = 0
    clusters_found:        int   = 0
    timeline_correlations: int   = 0
    leads_generated:       int   = 0
    infra_links_found:     int   = 0
    errors:                List[str] = field(default_factory=list)
    storage_backend:       str   = ""
    correlator_version:    str   = HIVE_CORRELATOR_VERSION


# ─────────────────────────────────────────────────────────────────────────────
# Utility
# ─────────────────────────────────────────────────────────────────────────────

def _utcnow() -> str:
    return datetime.datetime.utcnow().strftime(DATE_FMT)


def _ts_to_dt(ts_str: str) -> Optional[datetime.datetime]:
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ",
                 "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.datetime.strptime(ts_str.strip()[:26], fmt)
        except Exception:
            pass
    return None


def _strength(score: float) -> str:
    for threshold, label in STRENGTH_TIERS:
        if score >= threshold:
            return label
    return "WEAK"


def _priority(confidence: float) -> str:
    if confidence >= LEAD_PRIORITY_HIGH:
        return "HIGH"
    if confidence >= LEAD_PRIORITY_MEDIUM:
        return "MEDIUM"
    if confidence >= LEAD_PRIORITY_LOW:
        return "LOW"
    return "INFORMATIONAL"


def _is_noise_entity(etype: str, evalue: str) -> bool:
    """Return True if this entity is too common to be investigatively useful."""
    v = evalue.strip().lower()
    if etype == "IPV4" and (v in _NOISE_IPS or v.startswith("127.") or
                              v.startswith("0.") or v == "255.255.255.255"):
        return True
    if etype in ("IPV4","IPV6") and re.match(
            r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)", v):
        return True   # private range
    if etype == "DOMAIN" and v in _NOISE_DOMAINS:
        return True
    if etype == "DOMAIN" and any(v.endswith("." + d) for d in _NOISE_DOMAINS):
        return True
    if etype == "ANDROID_PACKAGE" and v.startswith(_NOISE_PACKAGES_PREFIX):
        return True
    if etype == "PHONE" and v in _NOISE_PHONES:
        return True
    return False


def _score_pair(entity_weights: List[float]) -> float:
    """
    Aggregate confidence score for a device pair from per-entity weights.

    The highest-weight entity dominates; additional shared entities provide
    diminishing-returns bonuses so the total is bounded at 1.0.
    """
    if not entity_weights:
        return 0.0
    ws = sorted(entity_weights, reverse=True)
    score = ws[0]
    for i, w in enumerate(ws[1:], start=1):
        score += w * (0.15 / i)
    return min(1.0, round(score, 4))


def _setup_logging(output_dir: str, verbose: bool = False) -> logging.Logger:
    os.makedirs(output_dir, exist_ok=True)
    path  = os.path.join(output_dir, f"hive_correlator_{datetime.date.today()}.log")
    level = logging.DEBUG if verbose else logging.INFO
    fmt   = logging.Formatter(LOG_FMT, datefmt=DATE_FMT)
    fh    = logging.FileHandler(path, encoding="utf-8")
    fh.setFormatter(fmt); fh.setLevel(level)
    ch    = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt); ch.setLevel(level)
    root  = logging.getLogger()
    root.setLevel(level); root.handlers.clear()
    root.addHandler(fh); root.addHandler(ch)
    return logging.getLogger("hive.correlator")


# ─────────────────────────────────────────────────────────────────────────────
# Abstract Store
# ─────────────────────────────────────────────────────────────────────────────

class AbstractStore(ABC):
    """Common interface for MongoDB and JSON-file storage backends."""

    @abstractmethod
    def save_run(self, run: CorrelationResult) -> None: ...

    @abstractmethod
    def save_devices(self, devices: List[Dict]) -> None: ...

    @abstractmethod
    def save_entity_network(self, entities: List[SharedEntity]) -> None: ...

    @abstractmethod
    def save_relationships(self, rels: List[DeviceRelationship]) -> None: ...

    @abstractmethod
    def save_clusters(self, clusters: List[DeviceCluster]) -> None: ...

    @abstractmethod
    def save_timeline_correlations(self, tcs: List[TimelineCorrelation]) -> None: ...

    @abstractmethod
    def save_leads(self, leads: List[InvestigativeLead]) -> None: ...

    @abstractmethod
    def save_infra_links(self, links: List[InfrastructureLink]) -> None: ...

    @abstractmethod
    def close(self) -> None: ...


# ─────────────────────────────────────────────────────────────────────────────
# MongoDB Store
# ─────────────────────────────────────────────────────────────────────────────

class MongoDBStore(AbstractStore):
    """
    Persists all correlation output into a MongoDB database.

    Each collection is indexed on case_id for fast per-case retrieval.
    Additional composite indexes support the typical query patterns of
    investigator.py and the visualisation dashboard.
    """

    def __init__(self, uri: str, db_name: str):
        self.client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=5000)
        # Fail fast if server unavailable
        self.client.admin.command("ping")
        self.db  = self.client[db_name]
        self.log = logging.getLogger("hive.store.mongo")
        self._ensure_indexes()

    def _ensure_indexes(self) -> None:
        c = self.db
        c.correlation_runs.create_index([("case_id", 1)])
        c.devices.create_index([("case_id", 1), ("device_id", 1)], unique=True)
        c.entity_network.create_index([("case_id", 1), ("entity_type", 1),
                                        ("entity_value", 1)])
        c.entity_network.create_index([("devices", 1)])
        c.device_relationships.create_index([("case_id", 1), ("device_a", 1),
                                               ("device_b", 1)])
        c.device_relationships.create_index([("confidence_score", -1)])
        c.device_relationships.create_index([("strength", 1)])
        c.device_clusters.create_index([("case_id", 1)])
        c.device_clusters.create_index([("devices", 1)])
        c.timeline_correlations.create_index([("case_id", 1),
                                               ("device_a", 1), ("device_b", 1)])
        c.investigative_leads.create_index([("case_id", 1), ("priority", 1)])
        c.investigative_leads.create_index([("confidence", -1)])
        c.infrastructure_graph.create_index([("case_id", 1),
                                               ("entity_a_val", 1),
                                               ("entity_b_val", 1)])

    def _col(self, name: str):
        return self.db[name]

    def _upsert_bulk(self, collection_name: str, docs: List[Dict],
                      key_fields: List[str]) -> None:
        if not docs:
            return
        col   = self._col(collection_name)
        ops   = []
        for doc in docs:
            filt  = {k: doc[k] for k in key_fields if k in doc}
            ops.append(pymongo.UpdateOne(filt, {"$set": doc}, upsert=True))
        if ops:
            try:
                col.bulk_write(ops, ordered=False)
            except pymongo.errors.BulkWriteError as exc:
                self.log.error(f"Bulk write error [{collection_name}]: {exc.details}")

    def save_run(self, run: CorrelationResult) -> None:
        d = asdict(run)
        self._col("correlation_runs").update_one(
            {"run_id": run.run_id}, {"$set": d}, upsert=True)

    def save_devices(self, devices: List[Dict]) -> None:
        self._upsert_bulk("devices", devices, ["case_id", "device_id"])

    def save_entity_network(self, entities: List[SharedEntity]) -> None:
        docs = [asdict(e) for e in entities]
        self._upsert_bulk("entity_network", docs, ["case_id", "entity_type",
                                                     "entity_value"])

    def save_relationships(self, rels: List[DeviceRelationship]) -> None:
        docs = [asdict(r) for r in rels]
        self._upsert_bulk("device_relationships", docs, ["relationship_id"])

    def save_clusters(self, clusters: List[DeviceCluster]) -> None:
        docs = [asdict(c) for c in clusters]
        self._upsert_bulk("device_clusters", docs, ["cluster_id"])

    def save_timeline_correlations(self, tcs: List[TimelineCorrelation]) -> None:
        docs = [asdict(t) for t in tcs]
        self._upsert_bulk("timeline_correlations", docs, ["correlation_id"])

    def save_leads(self, leads: List[InvestigativeLead]) -> None:
        docs = [asdict(l) for l in leads]
        self._upsert_bulk("investigative_leads", docs, ["lead_id"])

    def save_infra_links(self, links: List[InfrastructureLink]) -> None:
        docs = [asdict(l) for l in links]
        self._upsert_bulk("infrastructure_graph", docs, ["link_id"])

    def close(self) -> None:
        self.client.close()


# ─────────────────────────────────────────────────────────────────────────────
# JSON File Store  (fallback when MongoDB is unavailable)
# ─────────────────────────────────────────────────────────────────────────────

class JSONFileStore(AbstractStore):
    """
    Writes all correlation output as JSON files inside the case directory.

    Directory layout:
      <output_dir>/
        correlation/
          run_<run_id>.json
          devices.jsonl
          entity_network.jsonl
          device_relationships.jsonl
          device_clusters.jsonl
          timeline_correlations.jsonl
          investigative_leads.jsonl
          infrastructure_graph.jsonl
    """

    def __init__(self, output_dir: str):
        self.base = os.path.join(output_dir, "correlation")
        os.makedirs(self.base, exist_ok=True)
        self.log  = logging.getLogger("hive.store.json")
        self._handles: Dict[str, Any] = {}

    def _fh(self, name: str):
        if name not in self._handles:
            self._handles[name] = open(
                os.path.join(self.base, f"{name}.jsonl"), "a", encoding="utf-8")
        return self._handles[name]

    def _append(self, name: str, docs: List[Any]) -> None:
        fh = self._fh(name)
        for doc in docs:
            fh.write(json.dumps(doc if isinstance(doc, dict) else asdict(doc),
                                  default=str) + "\n")
        fh.flush()

    def save_run(self, run: CorrelationResult) -> None:
        path = os.path.join(self.base, f"run_{run.run_id[:8]}.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(asdict(run), fh, indent=2, default=str)
        self.log.info(f"Run summary → {path}")

    def save_devices(self, devices: List[Dict]) -> None:
        self._append("devices", devices)

    def save_entity_network(self, entities: List[SharedEntity]) -> None:
        self._append("entity_network", entities)

    def save_relationships(self, rels: List[DeviceRelationship]) -> None:
        self._append("device_relationships", rels)

    def save_clusters(self, clusters: List[DeviceCluster]) -> None:
        self._append("device_clusters", clusters)

    def save_timeline_correlations(self, tcs: List[TimelineCorrelation]) -> None:
        self._append("timeline_correlations", tcs)

    def save_leads(self, leads: List[InvestigativeLead]) -> None:
        self._append("investigative_leads", leads)

    def save_infra_links(self, links: List[InfrastructureLink]) -> None:
        self._append("infrastructure_graph", links)

    def close(self) -> None:
        for fh in self._handles.values():
            try:
                fh.close()
            except Exception:
                pass
        self._handles.clear()


# ─────────────────────────────────────────────────────────────────────────────
# SQLite Evidence Reader
# ─────────────────────────────────────────────────────────────────────────────

class EvidenceReader:
    """
    Reads the normalised evidence database produced by parser.py.

    All reads are read-only; we never modify the evidence database.
    """

    def __init__(self, db_path: str):
        if not os.path.exists(db_path):
            raise FileNotFoundError(f"Evidence DB not found: {db_path}")
        self.conn = sqlite3.connect(
            f"file:{db_path}?mode=ro", uri=True, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.log  = logging.getLogger("hive.evidence_reader")

    def _query(self, sql: str, params: tuple = ()) -> List[Dict]:
        cur = self.conn.cursor()
        cur.execute(sql, params)
        return [dict(r) for r in cur.fetchall()]

    def devices(self, case_id: str) -> List[Dict]:
        return self._query(
            "SELECT * FROM devices WHERE case_id = ?", (case_id,))

    def all_devices(self) -> List[Dict]:
        return self._query("SELECT * FROM devices")

    def entities(self, case_id: str) -> List[Dict]:
        return self._query(
            "SELECT entity_type, entity_value, device_id, artifact_type, "
            "first_seen, confidence FROM entities WHERE case_id = ?",
            (case_id,))

    def timeline(self, case_id: str, device_id: Optional[str] = None) -> List[Dict]:
        if device_id:
            return self._query(
                "SELECT * FROM timeline WHERE case_id = ? AND device_id = ? "
                "AND timestamp_utc != '' ORDER BY timestamp_utc",
                (case_id, device_id))
        return self._query(
            "SELECT * FROM timeline WHERE case_id = ? AND timestamp_utc != '' "
            "ORDER BY timestamp_utc", (case_id,))

    def case_ids(self) -> List[str]:
        rows = self._query("SELECT DISTINCT case_id FROM devices")
        return [r["case_id"] for r in rows]

    def artifact_counts(self, case_id: str) -> Dict[str, int]:
        rows = self._query(
            "SELECT artifact_type, COUNT(*) as n FROM artifacts "
            "WHERE case_id = ? GROUP BY artifact_type", (case_id,))
        return {r["artifact_type"]: r["n"] for r in rows}

    def close(self) -> None:
        self.conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# Entity Correlator
# ─────────────────────────────────────────────────────────────────────────────

class EntityCorrelator:
    """
    Groups raw entity rows by (entity_type, normalised_value), discards
    noise entries, and identifies entities shared across multiple devices.

    Returns SharedEntity objects ready for relationship scoring.
    """

    def __init__(self):
        self.log = logging.getLogger("hive.entity_correlator")

    def correlate(self, entity_rows: List[Dict],
                   case_id: str) -> List[SharedEntity]:
        # Group: (type, normalised_value) → list of rows
        groups: DefaultDict[Tuple[str, str], List[Dict]] = \
            collections.defaultdict(list)

        for row in entity_rows:
            etype = row.get("entity_type", "")
            evalue= row.get("entity_value", "").strip()
            if not etype or not evalue:
                continue
            if _is_noise_entity(etype, evalue):
                continue
            key = (etype, evalue.lower())
            groups[key].append(row)

        shared: List[SharedEntity] = []
        for (etype, evalue_norm), rows in groups.items():
            # Only keep entities appearing on ≥ 2 distinct devices
            devices = list({r["device_id"] for r in rows if r.get("device_id")})
            if len(devices) < 2:
                continue

            art_types = list({r.get("artifact_type","") for r in rows})
            ts_vals   = [r.get("first_seen","") for r in rows if r.get("first_seen")]
            ts_vals   = sorted(t for t in ts_vals if t)

            se = SharedEntity(
                entity_type   = etype,
                entity_value  = rows[0].get("entity_value", evalue_norm),
                devices        = devices,
                artifact_types = art_types,
                first_seen     = ts_vals[0]  if ts_vals else "",
                last_seen      = ts_vals[-1] if ts_vals else "",
                device_count   = len(devices),
                significance   = ENTITY_WEIGHTS.get(etype, 0.4),
            )
            shared.append(se)

        self.log.info(f"  Shared entities: {len(shared)} "
                       f"(from {len(entity_rows)} total)")
        return shared


# ─────────────────────────────────────────────────────────────────────────────
# Relationship Builder
# ─────────────────────────────────────────────────────────────────────────────

class RelationshipBuilder:
    """
    Converts SharedEntity objects into scored DeviceRelationship records.

    For N devices sharing an entity: N*(N-1)/2 device pairs are generated.
    All pairs from all shared entities are then aggregated; each pair's
    confidence score is calculated from its full set of shared entity weights.
    """

    def __init__(self, case_id: str, run_id: str,
                  min_confidence: float = DEFAULT_MIN_CONFIDENCE):
        self.case_id        = case_id
        self.run_id         = run_id
        self.min_confidence = min_confidence
        self.log            = logging.getLogger("hive.relationship_builder")

    def build(self, shared_entities: List[SharedEntity]) -> List[DeviceRelationship]:
        # Accumulate: (device_a, device_b) → list of (entity_type, value, weight)
        pair_map: DefaultDict[Tuple[str, str], List[Dict]] = \
            collections.defaultdict(list)

        for se in shared_entities:
            weight = ENTITY_WEIGHTS.get(se.entity_type, 0.4)
            # Generate all ordered pairs (a < b lexicographically for dedup)
            for dev_a, dev_b in itertools.combinations(sorted(se.devices), 2):
                pair_map[(dev_a, dev_b)].append({
                    "type":   se.entity_type,
                    "value":  se.entity_value,
                    "weight": weight,
                })

        relationships: List[DeviceRelationship] = []
        for (dev_a, dev_b), shared in pair_map.items():
            weights = [e["weight"] for e in shared]
            score   = _score_pair(weights)
            if score < self.min_confidence:
                continue

            rel = DeviceRelationship(
                case_id           = self.case_id,
                run_id            = self.run_id,
                device_a          = dev_a,
                device_b          = dev_b,
                relationship_types= list({e["type"] for e in shared}),
                shared_entities   = shared,
                confidence_score  = score,
                strength          = _strength(score),
                evidence_count    = len(shared),
            )
            relationships.append(rel)

        relationships.sort(key=lambda r: r.confidence_score, reverse=True)
        self.log.info(f"  Relationships: {len(relationships)} "
                       f"(min_confidence={self.min_confidence})")
        return relationships


# ─────────────────────────────────────────────────────────────────────────────
# Cluster Detector
# ─────────────────────────────────────────────────────────────────────────────

class ClusterDetector:
    """
    Detects groups of related devices using graph-based clustering.

    Strategy
      1. Build an undirected weighted graph:  nodes = devices,
         edges = relationships with weight = confidence_score.
      2. If networkx is available: use Louvain community detection for
         nuanced overlapping clusters.
      3. Fallback: simple BFS connected-components (any edge, any weight).

    Only clusters with ≥ 2 devices are returned.
    """

    def __init__(self, case_id: str, run_id: str):
        self.case_id = case_id
        self.run_id  = run_id
        self.log     = logging.getLogger("hive.cluster_detector")

    def detect(self, relationships: List[DeviceRelationship],
                shared_entities: List[SharedEntity]) -> List[DeviceCluster]:

        if not relationships:
            return []

        # Build adjacency
        adj: DefaultDict[str, Set[str]] = collections.defaultdict(set)
        edge_weight: Dict[Tuple[str, str], float] = {}
        for rel in relationships:
            adj[rel.device_a].add(rel.device_b)
            adj[rel.device_b].add(rel.device_a)
            edge_weight[(rel.device_a, rel.device_b)] = rel.confidence_score
            edge_weight[(rel.device_b, rel.device_a)] = rel.confidence_score

        # Community detection
        if HAS_NX and len(adj) > 2:
            communities = self._louvain(adj, edge_weight)
        else:
            communities = self._bfs_components(adj)

        # Build entity lookup per device
        device_ents: DefaultDict[str, List[str]] = collections.defaultdict(list)
        for se in shared_entities:
            for dev in se.devices:
                device_ents[dev].append(se.entity_type)

        # Build internal relationship count per cluster
        rel_index: Dict[Tuple[str,str], float] = {}
        for rel in relationships:
            rel_index[(rel.device_a, rel.device_b)] = rel.confidence_score

        clusters: List[DeviceCluster] = []
        for component in communities:
            if len(component) < 2:
                continue

            devs      = sorted(component)
            all_types = []
            for dev in devs:
                all_types.extend(device_ents[dev])
            type_counts = collections.Counter(all_types)
            dominant    = type_counts.most_common(5)

            # Cohesion = mean edge weight within cluster
            intra_edges = []
            for da, db in itertools.combinations(devs, 2):
                w = rel_index.get((da, db), rel_index.get((db, da), 0.0))
                if w > 0:
                    intra_edges.append(w)
            cohesion = (sum(intra_edges) / len(intra_edges)) if intra_edges else 0.0

            cluster = DeviceCluster(
                case_id        = self.case_id,
                run_id         = self.run_id,
                devices        = devs,
                device_count   = len(devs),
                cluster_type   = _infer_cluster_type(type_counts),
                cohesion_score = round(cohesion, 4),
                dominant_entities = [{"type": t, "count": c}
                                       for t, c in dominant],
                key_entity_types  = [t for t, _ in dominant],
                internal_relationships = len(intra_edges),
            )
            clusters.append(cluster)

        clusters.sort(key=lambda c: c.device_count, reverse=True)
        self.log.info(f"  Clusters: {len(clusters)} detected  "
                       f"({'Louvain' if HAS_NX else 'BFS'})")
        return clusters

    def _bfs_components(self, adj: Dict[str, Set[str]]) -> List[Set[str]]:
        visited: Set[str] = set()
        components: List[Set[str]] = []
        for start in list(adj.keys()):
            if start in visited:
                continue
            component: Set[str] = set()
            queue = [start]
            while queue:
                node = queue.pop(0)
                if node in visited:
                    continue
                visited.add(node)
                component.add(node)
                queue.extend(adj.get(node, set()) - visited)
            components.append(component)
        return components

    def _louvain(self, adj: Dict[str, Set[str]],
                  weights: Dict[Tuple[str,str], float]) -> List[Set[str]]:
        """Louvain community detection via networkx."""
        try:
            G = nx.Graph()
            for node, neighbours in adj.items():
                for nb in neighbours:
                    G.add_edge(node, nb,
                                weight=weights.get((node, nb), 1.0))
            communities = nx.community.louvain_communities(G, seed=42)
            return [set(c) for c in communities]
        except Exception as exc:
            self.log.warning(f"Louvain failed ({exc}), falling back to BFS")
            return self._bfs_components(adj)


# ─────────────────────────────────────────────────────────────────────────────
# Timeline Correlator
# ─────────────────────────────────────────────────────────────────────────────

class TimelineCorrelator:
    """
    Finds events on different devices that occurred within a configurable
    time window, indicating coordinated or synchronised activity.

    For large datasets the timeline is split into time buckets before
    pairwise comparison to keep complexity manageable.
    """

    def __init__(self, case_id: str, run_id: str,
                  window_minutes: int = DEFAULT_SYNC_WINDOW_MIN):
        self.case_id        = case_id
        self.run_id         = run_id
        self.window_seconds = window_minutes * 60
        self.log            = logging.getLogger("hive.timeline_correlator")

    def correlate(self, reader: EvidenceReader,
                   related_pairs: List[Tuple[str, str]]) -> List[TimelineCorrelation]:
        if not related_pairs:
            return []

        # Load timeline once, indexed by device
        all_events = reader.timeline(self.case_id)
        by_device: DefaultDict[str, List[Dict]] = collections.defaultdict(list)
        for ev in all_events:
            if ev.get("timestamp_utc") and ev.get("device_id"):
                by_device[ev["device_id"]].append(ev)

        results: List[TimelineCorrelation] = []
        seen_pairs: Set[Tuple[str, str]] = set()

        for dev_a, dev_b in related_pairs:
            pair_key = (min(dev_a, dev_b), max(dev_a, dev_b))
            if pair_key in seen_pairs:
                continue
            seen_pairs.add(pair_key)

            events_a = by_device.get(dev_a, [])
            events_b = by_device.get(dev_b, [])
            if not events_a or not events_b:
                continue

            syncs = self._find_sync_events(dev_a, dev_b, events_a, events_b)
            results.extend(syncs)

        self.log.info(f"  Timeline correlations: {len(results)}")
        return results

    def _find_sync_events(self, dev_a: str, dev_b: str,
                           events_a: List[Dict],
                           events_b: List[Dict]) -> List[TimelineCorrelation]:
        """
        O(N·M) comparison capped to avoid blowup on large event sets.
        We sample at most 500 events per device for the window search.
        """
        MAX_EVENTS = 500
        ea = events_a[-MAX_EVENTS:] if len(events_a) > MAX_EVENTS else events_a
        eb = events_b[-MAX_EVENTS:] if len(events_b) > MAX_EVENTS else events_b

        correlations: List[TimelineCorrelation] = []
        seen: Set[Tuple[str, str]] = set()

        for ev_a in ea:
            dt_a = _ts_to_dt(ev_a.get("timestamp_utc", ""))
            if not dt_a:
                continue
            for ev_b in eb:
                dt_b = _ts_to_dt(ev_b.get("timestamp_utc", ""))
                if not dt_b:
                    continue
                delta = abs((dt_a - dt_b).total_seconds())
                if delta > self.window_seconds:
                    continue
                # Deduplicate by event_id pair
                pair_key = (ev_a.get("event_id",""), ev_b.get("event_id",""))
                if pair_key in seen:
                    continue
                seen.add(pair_key)

                # Score: closer in time → higher score
                sync_score = round(1.0 - (delta / self.window_seconds), 4)

                tc = TimelineCorrelation(
                    case_id       = self.case_id,
                    run_id        = self.run_id,
                    device_a      = dev_a,
                    device_b      = dev_b,
                    event_a       = {k: ev_a.get(k,"")
                                     for k in ("event_id","event_type",
                                                "description","timestamp_utc")},
                    event_b       = {k: ev_b.get(k,"")
                                     for k in ("event_id","event_type",
                                                "description","timestamp_utc")},
                    delta_seconds = round(delta, 1),
                    sync_score    = sync_score,
                )
                correlations.append(tc)

                # Limit per-pair to top-50 most synchronised events
                if len(correlations) >= 50 * len(seen):
                    break

        # Return only the best 200 per pair
        correlations.sort(key=lambda t: t.sync_score, reverse=True)
        return correlations[:200]


# ─────────────────────────────────────────────────────────────────────────────
# Lead Generator
# ─────────────────────────────────────────────────────────────────────────────

class LeadGenerator:
    """
    Synthesises investigative leads from relationships, clusters, and shared
    entities, ranking them by priority and confidence.

    Lead types
      DEFINITIVE_LINK    — Two devices share a uniquely attributable entity
      CRYPTO_LINK        — Shared cryptocurrency wallet
      IMEI_REUSE         — Same IMEI on multiple devices (physical reuse / cloning)
      CLUSTER_ALERT      — A cluster of 3+ connected devices
      PHISHING_INFRA     — Multiple devices share domains / URLs
      BOTNET_INDICATOR   — Multiple devices share C2 IP addresses
      SYNCHRONIZED_OPS   — Highly synchronised activity across devices
      COMMON_CREDENTIAL  — Same username/password-hash across devices
    """

    def __init__(self, case_id: str, run_id: str):
        self.case_id = case_id
        self.run_id  = run_id
        self.log     = logging.getLogger("hive.lead_generator")

    def generate(self, relationships: List[DeviceRelationship],
                  shared_entities:   List[SharedEntity],
                  clusters:          List[DeviceCluster],
                  tl_correlations:   List[TimelineCorrelation]) -> List[InvestigativeLead]:
        leads: List[InvestigativeLead] = []

        leads.extend(self._leads_from_relationships(relationships))
        leads.extend(self._leads_from_entities(shared_entities))
        leads.extend(self._leads_from_clusters(clusters))
        leads.extend(self._leads_from_timeline(tl_correlations))

        # Deduplicate + sort by confidence descending
        seen_titles: Set[str] = set()
        unique: List[InvestigativeLead] = []
        for lead in sorted(leads, key=lambda l: l.confidence, reverse=True):
            if lead.title not in seen_titles:
                seen_titles.add(lead.title)
                unique.append(lead)

        self.log.info(f"  Leads generated: {len(unique)}")
        return unique

    def _mk_lead(self, lead_type: str, title: str, desc: str,
                  devices: List[str], entities: List[Dict],
                  confidence: float, tags: List[str] = None) -> InvestigativeLead:
        return InvestigativeLead(
            case_id     = self.case_id,
            run_id      = self.run_id,
            lead_type   = lead_type,
            priority    = _priority(confidence),
            title       = title,
            description = desc,
            devices     = devices,
            entities    = entities,
            confidence  = round(confidence, 4),
            tags        = tags or [],
        )

    def _leads_from_relationships(self,
                                    rels: List[DeviceRelationship]) -> List[InvestigativeLead]:
        leads: List[InvestigativeLead] = []
        for rel in rels:
            if rel.confidence_score < LEAD_PRIORITY_LOW:
                continue
            ents  = rel.shared_entities[:5]
            types = ", ".join(sorted({e["type"] for e in ents}))
            desc  = (f"Devices {rel.device_a} and {rel.device_b} share "
                     f"{rel.evidence_count} entity/entities ({types}). "
                     f"Confidence: {rel.confidence_score:.2f} [{rel.strength}].")
            tags = [rel.strength, "DEVICE_LINK"] + rel.relationship_types[:3]
            leads.append(self._mk_lead(
                "DEFINITIVE_LINK",
                f"{rel.strength} link: {rel.device_a} ↔ {rel.device_b}",
                desc, [rel.device_a, rel.device_b], ents,
                rel.confidence_score, tags))
        return leads

    def _leads_from_entities(self,
                               entities: List[SharedEntity]) -> List[InvestigativeLead]:
        leads: List[InvestigativeLead] = []
        for se in entities:
            if se.device_count < 2:
                continue
            conf    = se.significance * min(1.0, 0.7 + se.device_count * 0.1)
            devlist = se.devices[:10]
            ent_doc = {"type": se.entity_type, "value": se.entity_value}

            # Crypto wallet
            if se.entity_type in ("CRYPTO_BTC", "CRYPTO_ETH"):
                leads.append(self._mk_lead(
                    "CRYPTO_LINK",
                    f"Shared {se.entity_type} wallet across {se.device_count} device(s)",
                    f"Wallet {se.entity_value[:30]}… found on: {', '.join(devlist)}",
                    devlist, [ent_doc], min(1.0, conf),
                    ["CRYPTO", "HIGH_VALUE"]))

            # IMEI reuse (same device ID on multiple acquisitions)
            elif se.entity_type == "IMEI":
                leads.append(self._mk_lead(
                    "IMEI_REUSE",
                    f"IMEI {se.entity_value} on {se.device_count} device(s)",
                    f"Physical device identifier shared — possible cloning or dual acquisition.",
                    devlist, [ent_doc], min(1.0, conf),
                    ["IMEI", "DEVICE_REUSE"]))

            # High-significance entity on 3+ devices
            elif se.significance >= 0.75 and se.device_count >= 3:
                leads.append(self._mk_lead(
                    "DEFINITIVE_LINK",
                    f"High-value {se.entity_type} on {se.device_count} devices",
                    f"Entity '{se.entity_value[:50]}' appears on {se.device_count} device(s).",
                    devlist, [ent_doc], conf,
                    [se.entity_type, "MULTI_DEVICE"]))

        return leads

    def _leads_from_clusters(self,
                               clusters: List[DeviceCluster]) -> List[InvestigativeLead]:
        leads: List[InvestigativeLead] = []
        for cl in clusters:
            if cl.device_count < 2:
                continue
            conf = cl.cohesion_score
            desc = (f"Cluster of {cl.device_count} device(s) "
                    f"[{cl.cluster_type}] with cohesion {cl.cohesion_score:.2f}. "
                    f"Dominant entity types: {', '.join(cl.key_entity_types[:4])}.")
            leads.append(self._mk_lead(
                "CLUSTER_ALERT",
                f"{cl.cluster_type}: {cl.device_count} linked device(s) [{cl.cluster_id}]",
                desc, cl.devices[:20],
                [{"type": e["type"], "count": e["count"]}
                  for e in cl.dominant_entities],
                min(1.0, conf + 0.1 * math.log1p(cl.device_count)),
                [cl.cluster_type, "CLUSTER"]))
        return leads

    def _leads_from_timeline(self,
                               tcs: List[TimelineCorrelation]) -> List[InvestigativeLead]:
        if not tcs:
            return []
        # Group by device pair
        pair_syncs: DefaultDict[Tuple[str,str], List[float]] = \
            collections.defaultdict(list)
        for tc in tcs:
            pair_syncs[(tc.device_a, tc.device_b)].append(tc.sync_score)

        leads: List[InvestigativeLead] = []
        for (da, db), scores in pair_syncs.items():
            if len(scores) < 3:
                continue
            mean_sync = sum(scores) / len(scores)
            if mean_sync < 0.5:
                continue
            leads.append(self._mk_lead(
                "SYNCHRONIZED_OPS",
                f"Synchronised activity: {da} & {db} ({len(scores)} events)",
                f"{len(scores)} co-occurring events within sync window; "
                f"mean sync score: {mean_sync:.2f}.",
                [da, db], [],
                min(0.95, mean_sync),
                ["TIMELINE", "SYNCHRONIZED"]))
        return leads


# ─────────────────────────────────────────────────────────────────────────────
# Infrastructure Graph Builder
# ─────────────────────────────────────────────────────────────────────────────

class InfrastructureGraphBuilder:
    """
    Constructs entity-to-entity relationships that reveal shared infrastructure.

    Link types
      EMAIL_DOMAIN    — email address  → its domain
      URL_DOMAIN      — URL            → its root domain
      IP_CO_OCCURRENCE— Two IPs appear together across multiple devices
      DOMAIN_CO_OCCURRENCE — Two domains appear together
      PACKAGE_DOMAIN  — Android app package → domain it contacts
    """

    def __init__(self, case_id: str, run_id: str):
        self.case_id = case_id
        self.run_id  = run_id
        self.log     = logging.getLogger("hive.infra_graph")

    def build(self, shared_entities: List[SharedEntity]) -> List[InfrastructureLink]:
        links: List[InfrastructureLink] = []
        seen: Set[Tuple[str, str, str, str]] = set()

        def _add(at: str, av: str, bt: str, bv: str,
                  ltype: str, devs: List[str]) -> None:
            key = (at, av.lower(), bt, bv.lower())
            if key in seen:
                return
            seen.add(key)
            links.append(InfrastructureLink(
                case_id       = self.case_id,
                run_id        = self.run_id,
                entity_a_type = at,
                entity_a_val  = av,
                entity_b_type = bt,
                entity_b_val  = bv,
                link_type     = ltype,
                devices       = devs,
            ))

        # Build lookup: (type, value) → devices
        ent_devs: Dict[Tuple[str, str], List[str]] = {}
        for se in shared_entities:
            ent_devs[(se.entity_type, se.entity_value.lower())] = se.devices

        for se in shared_entities:
            v = se.entity_value

            # EMAIL → DOMAIN
            if se.entity_type == "EMAIL" and "@" in v:
                domain = v.split("@", 1)[1].lower().strip()
                if domain and not _is_noise_entity("DOMAIN", domain):
                    _add("EMAIL", v, "DOMAIN", domain, "EMAIL_DOMAIN", se.devices)

            # URL → DOMAIN
            if se.entity_type == "URL":
                m = re.search(r"https?://([^/\?#:]+)", v, re.I)
                if m:
                    domain = m.group(1).lower().strip()
                    if domain and not _is_noise_entity("DOMAIN", domain):
                        _add("URL", v, "DOMAIN", domain, "URL_DOMAIN", se.devices)

            # PACKAGE → any DOMAIN that appears on the same devices
            if se.entity_type == "ANDROID_PACKAGE":
                for (ot, ov), odevs in ent_devs.items():
                    if ot == "DOMAIN":
                        shared_devs = list(set(se.devices) & set(odevs))
                        if len(shared_devs) >= 2:
                            _add("ANDROID_PACKAGE", v, "DOMAIN", ov,
                                  "PACKAGE_DOMAIN", shared_devs)

        # Domain co-occurrence (two domains appear on ≥ 3 shared devices)
        domain_ents = [(se.entity_value, se.devices)
                        for se in shared_entities if se.entity_type == "DOMAIN"]
        for i in range(len(domain_ents)):
            for j in range(i + 1, len(domain_ents)):
                d1, devs1 = domain_ents[i]
                d2, devs2 = domain_ents[j]
                shared_devs = list(set(devs1) & set(devs2))
                if len(shared_devs) >= 2:
                    _add("DOMAIN", d1, "DOMAIN", d2,
                          "DOMAIN_CO_OCCURRENCE", shared_devs)

        self.log.info(f"  Infrastructure links: {len(links)}")
        return links


# ─────────────────────────────────────────────────────────────────────────────
# Cluster Type Inference
# ─────────────────────────────────────────────────────────────────────────────

def _infer_cluster_type(type_counts: collections.Counter) -> str:
    """
    Infer the nature of a device cluster from its dominant entity types.
    Returns a label suitable for display and downstream triage.
    """
    crypto   = type_counts.get("CRYPTO_BTC", 0) + type_counts.get("CRYPTO_ETH", 0)
    phones   = type_counts.get("PHONE", 0)
    emails   = type_counts.get("EMAIL", 0)
    domains  = type_counts.get("DOMAIN", 0) + type_counts.get("URL", 0)
    ips      = type_counts.get("IPV4", 0)  + type_counts.get("IPV6", 0)
    packages = type_counts.get("ANDROID_PACKAGE", 0)
    usernames= type_counts.get("USERNAME", 0)
    hashes   = (type_counts.get("HASH_MD5", 0)   +
                type_counts.get("HASH_SHA1", 0)   +
                type_counts.get("HASH_SHA256", 0))

    total = sum(type_counts.values()) or 1

    if crypto > 0 and crypto / total > 0.1:
        return "CRYPTOCURRENCY_FRAUD_NETWORK"
    if hashes > 3 and packages > 2:
        return "MALWARE_CAMPAIGN"
    if domains > phones and domains / total > 0.25:
        return "PHISHING_INFRASTRUCTURE"
    if ips > phones and ips / total > 0.25:
        return "BOTNET_INFRASTRUCTURE"
    if phones >= 3 and phones / total > 0.25:
        return "COMMUNICATION_NETWORK"
    if usernames >= 3:
        return "SHARED_CREDENTIAL_RING"
    if emails >= 3:
        return "COMMON_EMAIL_NETWORK"
    return "ORGANIZED_CRIMINAL_GROUP"


# ─────────────────────────────────────────────────────────────────────────────
# HIVE Correlator — Main Orchestrator
# ─────────────────────────────────────────────────────────────────────────────

class HIVECorrelator:
    """
    Orchestrates the full correlation pipeline.

    Stages
      1.  Read devices and entities from parser SQLite database
      2.  Entity correlation   → SharedEntity list
      3.  Relationship building → DeviceRelationship list  (scored + filtered)
      4.  Cluster detection    → DeviceCluster list
      5.  Timeline correlation → TimelineCorrelation list
      6.  Lead generation      → InvestigativeLead list
      7.  Infrastructure graph → InfrastructureLink list
      8.  Persist to MongoDB / JSON store
      9.  Write CorrelationResult report

    Future integration hooks (stubs)
      self._send_to_kafka(records)     — stream leads to Apache Kafka topic
      self._index_elasticsearch(docs)  — push relationships to ES for dashboards
      self._push_neo4j(rels)           — load graph edges into Neo4j
    """

    def __init__(self, evidence_db: str, case_id: str,
                  store: AbstractStore,
                  sync_window_min: int  = DEFAULT_SYNC_WINDOW_MIN,
                  min_confidence:  float = DEFAULT_MIN_CONFIDENCE,
                  workers:         int   = DEFAULT_WORKERS):
        self.evidence_db      = evidence_db
        self.case_id          = case_id
        self.store            = store
        self.sync_window_min  = sync_window_min
        self.min_confidence   = min_confidence
        self.workers          = workers
        self.log              = logging.getLogger("hive.correlator")
        self._result          = CorrelationResult(
            case_id      = case_id,
            evidence_db  = evidence_db,
            started_at   = _utcnow(),
        )

    def run(self) -> CorrelationResult:
        run_id = self._result.run_id
        log    = self.log

        log.info("═" * 70)
        log.info(f"  HIVE Correlator  v{HIVE_CORRELATOR_VERSION}")
        log.info(f"  Case    : {self.case_id}")
        log.info(f"  DB      : {self.evidence_db}")
        log.info(f"  Sync Δt : {self.sync_window_min} min  "
                  f"Min-conf: {self.min_confidence}")
        log.info(f"  NetworkX: {'YES' if HAS_NX else 'NO'}  "
                  f"MongoDB : {'YES' if HAS_MONGO else 'NO'}")
        log.info("═" * 70)

        try:
            reader = EvidenceReader(self.evidence_db)
        except FileNotFoundError as exc:
            log.error(str(exc))
            self._result.errors.append(str(exc))
            self._result.completed_at = _utcnow()
            return self._result

        # ── Stage 1: Load raw data ────────────────────────────
        log.info("[1/7] Loading evidence …")
        devices      = reader.devices(self.case_id)
        if not devices:
            log.warning("  No devices found for this case ID; trying all devices")
            devices = reader.all_devices()

        entity_rows  = reader.entities(self.case_id)
        self._result.devices_analyzed  = len(devices)
        self._result.entities_analyzed = len(entity_rows)
        log.info(f"  Devices: {len(devices)}  |  Entity rows: {len(entity_rows)}")

        # Persist device profiles
        self.store.save_devices([dict(d) for d in devices])

        # ── Stage 2: Entity correlation ───────────────────────
        log.info("[2/7] Correlating entities …")
        correlator   = EntityCorrelator()
        shared_ents  = correlator.correlate(entity_rows, self.case_id)

        # Tag each shared entity with case/run IDs and save
        tagged_ents = [SharedEntity(**{**asdict(se),
                                        **{"device_count": len(se.devices)}})
                        for se in shared_ents]
        self.store.save_entity_network(tagged_ents)
        self._result.shared_entities_found = len(shared_ents)

        # ── Stage 3: Relationship building ────────────────────
        log.info("[3/7] Building device relationships …")
        builder      = RelationshipBuilder(self.case_id, run_id,
                                            self.min_confidence)
        relationships= builder.build(shared_ents)
        self.store.save_relationships(relationships)
        self._result.relationships_found = len(relationships)
        log.info(f"  {len(relationships)} relationships  "
                  f"(DEFINITIVE: {sum(1 for r in relationships if r.strength=='DEFINITIVE')}  "
                  f"STRONG: {sum(1 for r in relationships if r.strength=='STRONG')})")

        # ── Stage 4: Cluster detection ────────────────────────
        log.info("[4/7] Detecting clusters …")
        detector     = ClusterDetector(self.case_id, run_id)
        clusters     = detector.detect(relationships, shared_ents)
        self.store.save_clusters(clusters)
        self._result.clusters_found = len(clusters)
        for cl in clusters:
            log.info(f"  {cl.cluster_id}  {cl.cluster_type}  "
                      f"{cl.device_count} devices  cohesion={cl.cohesion_score:.2f}")

        # ── Stage 5: Timeline correlation ─────────────────────
        log.info("[5/7] Correlating timelines …")
        rel_pairs     = [(r.device_a, r.device_b) for r in relationships]
        tl_corr       = TimelineCorrelator(self.case_id, run_id,
                                            self.sync_window_min)
        tl_results    = tl_corr.correlate(reader, rel_pairs)
        self.store.save_timeline_correlations(tl_results)
        self._result.timeline_correlations = len(tl_results)

        # ── Stage 6: Lead generation ──────────────────────────
        log.info("[6/7] Generating investigative leads …")
        lead_gen      = LeadGenerator(self.case_id, run_id)
        leads         = lead_gen.generate(relationships, shared_ents,
                                           clusters, tl_results)
        self.store.save_leads(leads)
        self._result.leads_generated = len(leads)
        high   = sum(1 for l in leads if l.priority == "HIGH")
        medium = sum(1 for l in leads if l.priority == "MEDIUM")
        log.info(f"  {len(leads)} leads  (HIGH:{high}  MEDIUM:{medium})")

        # ── Stage 7: Infrastructure graph ─────────────────────
        log.info("[7/7] Building infrastructure graph …")
        infra_builder = InfrastructureGraphBuilder(self.case_id, run_id)
        infra_links   = infra_builder.build(shared_ents)
        self.store.save_infra_links(infra_links)
        self._result.infra_links_found = len(infra_links)

        # ── Finalise ──────────────────────────────────────────
        self._result.completed_at = _utcnow()
        self.store.save_run(self._result)
        reader.close()

        self._print_summary(leads, clusters)
        return self._result

    # ── Future integration stubs ──────────────────────────────

    def _send_to_kafka(self, records: List[Dict]) -> None:
        """Stub: stream leads/relationships to Apache Kafka for real-time consumers."""
        pass

    def _index_elasticsearch(self, docs: List[Dict]) -> None:
        """Stub: push correlation results into Elasticsearch for dashboards."""
        pass

    def _push_neo4j(self, relationships: List[DeviceRelationship]) -> None:
        """Stub: load relationship graph edges into Neo4j for graph queries."""
        pass

    # ── Internal ──────────────────────────────────────────────

    def _print_summary(self, leads: List[InvestigativeLead],
                        clusters: List[DeviceCluster]) -> None:
        r = self._result
        self.log.info("─" * 70)
        self.log.info(f"  Devices analysed    : {r.devices_analyzed}")
        self.log.info(f"  Entities analysed   : {r.entities_analyzed}")
        self.log.info(f"  Shared entities     : {r.shared_entities_found}")
        self.log.info(f"  Relationships       : {r.relationships_found}")
        self.log.info(f"  Clusters            : {r.clusters_found}")
        self.log.info(f"  Timeline corrs.     : {r.timeline_correlations}")
        self.log.info(f"  Leads generated     : {r.leads_generated}")
        self.log.info(f"  Infra links         : {r.infra_links_found}")
        self.log.info(f"  Duration            : "
                       f"{r.started_at} → {r.completed_at}")

        if leads:
            self.log.info("")
            self.log.info("  TOP INVESTIGATIVE LEADS")
            self.log.info("  " + "─" * 50)
            for lead in leads[:10]:
                self.log.info(f"  [{lead.priority:^12}] {lead.title[:60]}")

        if clusters:
            self.log.info("")
            self.log.info("  DETECTED CLUSTERS")
            self.log.info("  " + "─" * 50)
            for cl in clusters:
                self.log.info(f"  {cl.cluster_id}  {cl.cluster_type}  "
                               f"{cl.device_count} devices")
        self.log.info("─" * 70)


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def build_cli() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="correlator.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "HIVE Platform  —  Stage 3: Intelligence Correlation Engine  v"
            + HIVE_CORRELATOR_VERSION + "\n"
            "Discovers relationships, clusters, and leads across seized devices.\n\n"
            "Requires: pip install pymongo  (optional: pip install networkx)"
        ),
        epilog="""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 QUICK-START EXAMPLES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Full pipeline (MongoDB):
  python3 correlator.py \\
    --db /evidence/CASE-001/hive_evidence.db \\
    --case-id CASE-001 \\
    --mongo-uri mongodb://localhost:27017

JSON-only (no MongoDB required):
  python3 correlator.py \\
    --db /evidence/CASE-001/hive_evidence.db \\
    --case-id CASE-001 --no-mongo

Custom sync window and confidence:
  python3 correlator.py \\
    --db /evidence/CASE-001/hive_evidence.db \\
    --case-id CASE-001 --sync-window 60 --min-confidence 0.35

Query MongoDB after correlation:
  mongosh hive --eval \\
    "db.investigative_leads.find({case_id:'CASE-001',priority:'HIGH'}).pretty()"

  mongosh hive --eval \\
    "db.device_relationships.find({case_id:'CASE-001',strength:'DEFINITIVE'}).pretty()"
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
    )
    g = p.add_argument_group("Input")
    g.add_argument("--db",       required=True, metavar="SQLITE_DB",
                    help="Path to hive_evidence.db from parser.py")
    g.add_argument("--case-id",  required=True, metavar="ID",
                    help="Case identifier (must match parser output)")

    g2 = p.add_argument_group("Storage")
    g2.add_argument("--mongo-uri", default=DEFAULT_MONGO_URI,
                     help=f"MongoDB connection URI (default: {DEFAULT_MONGO_URI})")
    g2.add_argument("--mongo-db",  default=DEFAULT_MONGO_DB,
                     help=f"MongoDB database name (default: {DEFAULT_MONGO_DB})")
    g2.add_argument("--no-mongo",  action="store_true",
                     help="Skip MongoDB; write JSON files instead")
    g2.add_argument("--output",    metavar="DIR",
                     help="Output directory for JSON fallback files "
                          "(default: same dir as --db)")

    g3 = p.add_argument_group("Correlation Parameters")
    g3.add_argument("--sync-window",    type=int, default=DEFAULT_SYNC_WINDOW_MIN,
                     metavar="MINUTES",
                     help=f"Timeline co-occurrence window (default: {DEFAULT_SYNC_WINDOW_MIN}m)")
    g3.add_argument("--min-confidence", type=float, default=DEFAULT_MIN_CONFIDENCE,
                     metavar="FLOAT",
                     help=f"Minimum relationship confidence (default: {DEFAULT_MIN_CONFIDENCE})")
    g3.add_argument("--workers", type=int, default=DEFAULT_WORKERS,
                     help=f"Parallel workers for heavy stages (default: {DEFAULT_WORKERS})")

    g4 = p.add_argument_group("Operation")
    g4.add_argument("-v","--verbose", action="store_true",
                     help="Debug-level logging")
    return p


def _build_store(args: argparse.Namespace, output_dir: str) -> AbstractStore:
    """Construct the appropriate storage backend."""
    log = logging.getLogger("hive.correlator")
    if not args.no_mongo and HAS_MONGO:
        try:
            store = MongoDBStore(args.mongo_uri, args.mongo_db)
            log.info(f"Storage: MongoDB  uri={args.mongo_uri}  db={args.mongo_db}")
            return store
        except Exception as exc:
            log.warning(f"MongoDB unavailable ({exc}); falling back to JSON files")

    if not HAS_MONGO and not args.no_mongo:
        log.warning("pymongo not installed (pip install pymongo); "
                     "using JSON file fallback")

    store = JSONFileStore(output_dir)
    log.info(f"Storage: JSON files  →  {os.path.join(output_dir, 'correlation/')}")
    return store


def main() -> int:
    cli  = build_cli()
    args = cli.parse_args()

    output_dir = args.output or os.path.dirname(os.path.abspath(args.db))
    log = _setup_logging(output_dir, args.verbose)

    store = _build_store(args, output_dir)
    store_name = ("MongoDB" if isinstance(store, MongoDBStore) else "JSON")

    correlator = HIVECorrelator(
        evidence_db    = args.db,
        case_id        = args.case_id,
        store          = store,
        sync_window_min= args.sync_window,
        min_confidence = args.min_confidence,
        workers        = args.workers,
    )
    correlator._result.storage_backend = store_name

    result = correlator.run()
    store.close()

    print("\n" + "─" * 60)
    print(f"  Case                : {result.case_id}")
    print(f"  Storage backend     : {store_name}")
    print(f"  Shared entities     : {result.shared_entities_found}")
    print(f"  Relationships       : {result.relationships_found}")
    print(f"  Clusters            : {result.clusters_found}")
    print(f"  Timeline corrs.     : {result.timeline_correlations}")
    print(f"  Investigative leads : {result.leads_generated}")
    print(f"  Infrastructure links: {result.infra_links_found}")
    if result.errors:
        print(f"  Errors              : {len(result.errors)}")
    print("─" * 60)

    return 0 if not result.errors else 2


if __name__ == "__main__":
    sys.exit(main())
