"""
app.py  —  HIVE Command Center · Flask Application
═══════════════════════════════════════════════════════════════════════
Stage 6 of the HIVE (High-scale Investigation and Verification Engine)
platform.  Unifies all upstream intelligence into a single web-based
investigative workspace.

Stack
  Flask + Jinja2   — server-side rendering
  HTMX             — dynamic partial updates without page reloads
  Bootstrap 5      — responsive dark-theme layout
  Cytoscape.js     — interactive relationship graph visualization
  MongoDB          — primary data source (from correlator + hive_ai)

Prerequisites
  pip install flask pymongo python-dotenv
  (optional) NVIDIA_API_KEY env var for live AI queries

Run
  python3 app.py                       # development
  gunicorn -w 4 -b 0.0.0.0:5000 app:app  # production
"""

from __future__ import annotations

import os
import re
import sys
import json
import hashlib
import datetime
import functools
import traceback
from typing import Optional, List, Dict, Any

from flask import (Flask, render_template, request, jsonify,
                   redirect, url_for, session, abort, Response)

try:
    import pymongo
    from pymongo import MongoClient
    HAS_MONGO = True
except ImportError:
    HAS_MONGO = False
    print("[!] pymongo not installed — pip install pymongo", file=sys.stderr)

# Optional: HIVE-AI integration
try:
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    from hive_ai import (HIVEAI, QueryPlanner, NIMClient,
                          ContextRetriever, PromptBuilder, AnalysisEngine,
                          AISession)
    HAS_HIVE_AI = True
except ImportError:
    HAS_HIVE_AI = False

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

MONGO_URI    = os.environ.get("HIVE_MONGO_URI",  "mongodb://localhost:27017")
MONGO_DB     = os.environ.get("HIVE_MONGO_DB",   "hive")
NIM_API_KEY  = os.environ.get("NVIDIA_API_KEY",  "")
NIM_MODEL    = os.environ.get("HIVE_AI_MODEL",
               "nvidia/llama-3.3-nemotron-super-49b-v1")
SECRET_KEY   = os.environ.get("HIVE_SECRET_KEY", "hive-dev-secret-change-in-prod")
DEBUG        = os.environ.get("HIVE_DEBUG", "1") == "1"
PAGE_SIZE    = 25

# Cluster-type colour palette
CLUSTER_COLORS = [
    "#00d4aa","#7ee787","#ffa657","#79c0ff",
    "#bc8cff","#ff7b72","#f0883e","#58a6ff",
]

STRENGTH_COLORS = {
    "DEFINITIVE": "#ff4444",
    "STRONG":     "#ffa500",
    "MODERATE":   "#00d4aa",
    "WEAK":       "#6e7681",
}

PRIORITY_COLORS = {
    "HIGH":          "danger",
    "MEDIUM":        "warning",
    "LOW":           "success",
    "INFORMATIONAL": "secondary",
}

DEVICE_TYPE_ICONS = {
    "android": "🤖",
    "windows": "🖥️",
    "linux":   "🐧",
    "ios":     "📱",
    "macos":   "🍎",
    "unknown": "❓",
}

ENTITY_TYPE_BADGES = {
    "PHONE":           ("📞", "#00d4aa"),
    "EMAIL":           ("✉️", "#79c0ff"),
    "IPV4":            ("🌐", "#bc8cff"),
    "IPV6":            ("🌐", "#bc8cff"),
    "DOMAIN":          ("🔗", "#f0883e"),
    "URL":             ("🔗", "#f0883e"),
    "CRYPTO_BTC":      ("₿", "#ffa657"),
    "CRYPTO_ETH":      ("Ξ", "#7ee787"),
    "MAC_ADDRESS":     ("📡", "#58a6ff"),
    "IMEI":            ("📱", "#00d4aa"),
    "USERNAME":        ("👤", "#ff7b72"),
    "HASH_SHA256":     ("#", "#6e7681"),
    "HASH_MD5":        ("#", "#6e7681"),
    "ANDROID_PACKAGE": ("📦", "#7ee787"),
    "WIFI_SSID":       ("📶", "#58a6ff"),
}

# ─────────────────────────────────────────────────────────────────────────────
# Flask App Setup
# ─────────────────────────────────────────────────────────────────────────────

app = Flask(__name__)
app.secret_key = SECRET_KEY


# ─────────────────────────────────────────────────────────────────────────────
# MongoDB Connection
# ─────────────────────────────────────────────────────────────────────────────

_mongo_client: Optional[MongoClient] = None

def get_client() -> Optional[MongoClient]:
    global _mongo_client
    if not HAS_MONGO:
        return None
    if _mongo_client is None:
        try:
            _mongo_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000)
            _mongo_client.admin.command("ping")
        except Exception as exc:
            app.logger.error(f"MongoDB connection failed: {exc}")
            _mongo_client = None
    return _mongo_client

def get_db():
    client = get_client()
    if client is None:
        abort(503, "MongoDB unavailable")
    return client[MONGO_DB]


# ─────────────────────────────────────────────────────────────────────────────
# Jinja2 Filters & Globals
# ─────────────────────────────────────────────────────────────────────────────

@app.template_filter("truncate_id")
def truncate_id(s: str, n: int = 8) -> str:
    return str(s)[:n]

@app.template_filter("pct")
def pct(v) -> str:
    try:
        return f"{float(v)*100:.0f}%"
    except Exception:
        return "—"

@app.template_filter("score_color")
def score_color(v) -> str:
    try:
        f = float(v)
        if f >= 0.8:  return "danger"
        if f >= 0.6:  return "warning"
        if f >= 0.4:  return "info"
        return "secondary"
    except Exception:
        return "secondary"

@app.template_filter("strength_badge")
def strength_badge(s: str) -> str:
    colors = {"DEFINITIVE":"danger","STRONG":"warning",
               "MODERATE":"info","WEAK":"secondary"}
    c = colors.get(s, "secondary")
    return f'<span class="badge bg-{c}">{s}</span>'

@app.template_filter("priority_badge")
def priority_badge(p: str) -> str:
    c = PRIORITY_COLORS.get(p, "secondary")
    return f'<span class="badge bg-{c}">{p}</span>'

@app.template_filter("entity_icon")
def entity_icon(etype: str) -> str:
    icon, _ = ENTITY_TYPE_BADGES.get(etype, ("🔍","#8b949e"))
    return icon

@app.template_filter("dt_fmt")
def dt_fmt(s: str) -> str:
    if not s:
        return "—"
    return str(s).replace("T"," ").replace("Z","")[:16]

@app.context_processor
def inject_globals():
    db = None
    try:
        db = get_db()
    except Exception:
        pass
    cases = []
    if db is not None:
        try:
            cases = sorted(db.devices.distinct("case_id"))
        except Exception:
            pass
    return {
        "all_cases":    cases,
        "current_case": request.args.get("case_id") or session.get("case_id",""),
        "has_ai":       bool(HAS_HIVE_AI and NIM_API_KEY),
        "nav_items": [
            ("Cases",         "index",         "🗂️"),
            ("Search",        "search",        "🔍"),
            ("Devices",       "devices",       "📱"),
            ("Clusters",      "clusters",      "🔗"),
            ("Leads",         "leads",         "⚡"),
            ("Graph",         "graph",         "🕸️"),
            ("Timeline",      "timeline",      "⏱️"),
            ("AI",            "ai_page",       "🧠"),
        ],
    }


# ─────────────────────────────────────────────────────────────────────────────
# Data Helpers
# ─────────────────────────────────────────────────────────────────────────────

def case_stats(db, case_id: str) -> Dict:
    run = db.correlation_runs.find_one(
        {"case_id": case_id}, {"_id": 0}, sort=[("completed_at", -1)]) or {}
    return {
        "case_id":       case_id,
        "devices":       db.devices.count_documents({"case_id": case_id}),
        "relationships": db.device_relationships.count_documents({"case_id": case_id}),
        "clusters":      db.device_clusters.count_documents({"case_id": case_id}),
        "leads_high":    db.investigative_leads.count_documents(
                           {"case_id": case_id, "priority": "HIGH"}),
        "leads_medium":  db.investigative_leads.count_documents(
                           {"case_id": case_id, "priority": "MEDIUM"}),
        "leads_low":     db.investigative_leads.count_documents(
                           {"case_id": case_id, "priority": "LOW"}),
        "shared_entities": run.get("shared_entities_found", 0),
        "entities_analyzed": run.get("entities_analyzed", 0),
        "run": run,
    }


def build_graph_data(db, case_id: str, mode: str = "relationships",
                      device_filter: str = "", min_score: float = 0.0) -> Dict:
    """Generate Cytoscape.js compatible elements dict."""
    nodes: List[Dict] = []
    edges: List[Dict] = []
    node_set: set = set()

    devices_raw = list(db.devices.find(
        {"case_id": case_id}, {"_id": 0, "manifest_json": 0}))
    device_map  = {d["device_id"]: d for d in devices_raw}

    # Cluster colour assignment
    cluster_color: Dict[str, str] = {}
    cluster_id_map: Dict[str, str] = {}
    clusters_raw = list(db.device_clusters.find({"case_id": case_id}, {"_id": 0}))
    for i, cl in enumerate(clusters_raw):
        col = CLUSTER_COLORS[i % len(CLUSTER_COLORS)]
        for dev in cl.get("devices", []):
            cluster_color[dev] = col
            cluster_id_map[dev] = cl.get("cluster_id", "")

    def _device_node(d: Dict) -> Dict:
        did   = d.get("device_id", "")
        dtype = d.get("device_type", "unknown")
        lbl   = (d.get("device_model") or did)[:20]
        return {"data": {
            "id":          did,
            "label":       lbl,
            "type":        "device",
            "device_type": dtype,
            "icon":        DEVICE_TYPE_ICONS.get(dtype, "❓"),
            "cluster_id":  cluster_id_map.get(did, ""),
            "color":       cluster_color.get(did, "#30363d"),
            "border":      "#00d4aa" if mode == "clusters" and did in cluster_color else "#30363d",
        }}

    if mode in ("relationships", "clusters"):
        # Ego-graph filter
        if device_filter:
            rels_raw = list(db.device_relationships.find(
                {"case_id": case_id,
                 "confidence_score": {"$gte": min_score},
                 "$or": [{"device_a": device_filter},
                          {"device_b": device_filter}]},
                {"_id": 0}))
            for r in rels_raw:
                node_set.add(r["device_a"])
                node_set.add(r["device_b"])
            node_set.add(device_filter)
        else:
            for d in devices_raw:
                node_set.add(d["device_id"])

        for did in node_set:
            if did in device_map:
                nodes.append(_device_node(device_map[did]))

        rels_raw = list(db.device_relationships.find(
            {"case_id": case_id, "confidence_score": {"$gte": min_score}},
            {"_id": 0}))
        for r in rels_raw:
            a, b = r.get("device_a",""), r.get("device_b","")
            if a in node_set and b in node_set:
                strength = r.get("strength", "WEAK")
                edges.append({"data": {
                    "id":     r.get("relationship_id", f"{a}-{b}"),
                    "source": a,
                    "target": b,
                    "strength": strength,
                    "color":  STRENGTH_COLORS.get(strength, "#6e7681"),
                    "score":  round(r.get("confidence_score", 0), 2),
                    "evidence_count": r.get("evidence_count", 0),
                    "types":  ", ".join(r.get("relationship_types", [])[:3]),
                    "width":  max(1, min(8, int(r.get("evidence_count", 1)))),
                }})

    elif mode == "entities":
        ents = list(db.entity_network.find(
            {"case_id": case_id, "device_count": {"$gte": 2}},
            {"_id": 0}).sort("significance", -1).limit(60))

        for e in ents:
            eid = "ent_" + hashlib.md5(
                e.get("entity_value","").encode()).hexdigest()[:10]
            etype = e.get("entity_type","")
            _, col = ENTITY_TYPE_BADGES.get(etype, ("🔍","#8b949e"))
            nodes.append({"data": {
                "id":           eid,
                "label":        str(e.get("entity_value",""))[:22],
                "type":         "entity",
                "entity_type":  etype,
                "color":        col,
                "device_count": e.get("device_count", 0),
            }})
            for dev in e.get("devices", []):
                if dev not in node_set and dev in device_map:
                    node_set.add(dev)
                    nodes.append(_device_node(device_map[dev]))
                edges.append({"data": {
                    "id":     f"{eid}_{dev}",
                    "source": dev,
                    "target": eid,
                    "type":   "has_entity",
                    "color":  "#30363d",
                    "width":  1,
                }})

    return {"elements": {"nodes": nodes, "edges": edges}}


# ─────────────────────────────────────────────────────────────────────────────
# Main Pages
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Case list / landing page."""
    db = get_db()
    case_ids = sorted(db.devices.distinct("case_id"))
    cases    = []
    for cid in case_ids:
        cases.append(case_stats(db, cid))
    return render_template("index.html", cases=cases)


@app.route("/case/<case_id>")
def case_view(case_id: str):
    """Case overview dashboard."""
    db     = get_db()
    session["case_id"] = case_id
    stats  = case_stats(db, case_id)
    leads  = list(db.investigative_leads.find(
        {"case_id": case_id}, {"_id": 0}).sort("confidence", -1).limit(8))
    rels   = list(db.device_relationships.find(
        {"case_id": case_id}, {"_id": 0}).sort("confidence_score", -1).limit(8))
    clusts = list(db.device_clusters.find(
        {"case_id": case_id}, {"_id": 0}).sort("device_count", -1).limit(6))
    ai_recs= list(db.ai_analyses.find(
        {"case_id": case_id}, {"_id": 0,
         "raw_response": 0}).sort("created_at", -1).limit(5))
    entity_types = list(db.entity_network.aggregate([
        {"$match": {"case_id": case_id}},
        {"$group": {"_id": "$entity_type", "count": {"$sum": 1}}},
        {"$sort":  {"count": -1}},
        {"$limit": 8},
    ]))
    return render_template("case.html",
        case_id=case_id, stats=stats, leads=leads,
        relationships=rels, clusters=clusts,
        ai_analyses=ai_recs, entity_types=entity_types)


@app.route("/devices")
def devices():
    case_id = request.args.get("case_id") or session.get("case_id","")
    if not case_id:
        return redirect(url_for("index"))
    db   = get_db()
    devs = list(db.devices.find(
        {"case_id": case_id}, {"_id": 0, "manifest_json": 0}))
    return render_template("devices.html", case_id=case_id, devices=devs)


@app.route("/device/<device_id>")
def device_view(device_id: str):
    case_id = request.args.get("case_id") or session.get("case_id","")
    db      = get_db()
    dev     = db.devices.find_one(
        {"device_id": device_id}, {"_id": 0, "manifest_json": 0})
    if not dev:
        abort(404, f"Device not found: {device_id}")
    rels    = list(db.device_relationships.find(
        {"case_id": case_id,
         "$or": [{"device_a": device_id}, {"device_b": device_id}]},
        {"_id": 0}).sort("confidence_score", -1).limit(15))
    clusts  = list(db.device_clusters.find(
        {"case_id": case_id, "devices": device_id}, {"_id": 0}))
    leads   = list(db.investigative_leads.find(
        {"case_id": case_id, "devices": device_id},
        {"_id": 0}).sort("confidence", -1).limit(10))
    shared_ents = list(db.entity_network.find(
        {"case_id": case_id, "devices": device_id, "device_count": {"$gte": 2}},
        {"_id": 0}).sort("significance", -1).limit(30))
    ai_analyses = list(db.ai_analyses.find(
        {"case_id": case_id, "session_id": {"$exists": True}},
        {"_id": 0, "raw_response": 0}).sort("created_at", -1).limit(3))
    tl_events   = list(db.timeline_correlations.find(
        {"case_id": case_id,
         "$or": [{"device_a": device_id}, {"device_b": device_id}]},
        {"_id": 0}).sort("delta_seconds", 1).limit(20))
    return render_template("device.html",
        device=dev, case_id=case_id, device_id=device_id,
        relationships=rels, clusters=clusts, leads=leads,
        shared_entities=shared_ents, ai_analyses=ai_analyses,
        timeline_events=tl_events)


@app.route("/cluster/<cluster_id>")
def cluster_view(cluster_id: str):
    case_id = request.args.get("case_id") or session.get("case_id","")
    db      = get_db()
    cl      = db.device_clusters.find_one({"cluster_id": cluster_id}, {"_id": 0})
    if not cl:
        abort(404, f"Cluster not found: {cluster_id}")
    members      = cl.get("devices", [])
    member_devs  = list(db.devices.find(
        {"device_id": {"$in": members}}, {"_id": 0, "manifest_json": 0}))
    shared_ents  = list(db.entity_network.find(
        {"case_id": case_id, "devices": {"$all": members[:2]},
         "device_count": {"$gte": 2}},
        {"_id": 0}).sort("significance", -1).limit(25))
    intra_rels   = list(db.device_relationships.find(
        {"case_id": case_id,
         "device_a": {"$in": members},
         "device_b": {"$in": members}},
        {"_id": 0}).sort("confidence_score", -1))
    leads        = list(db.investigative_leads.find(
        {"case_id": case_id, "devices": {"$in": members}},
        {"_id": 0}).sort("confidence", -1).limit(8))
    return render_template("cluster.html",
        cluster=cl, cluster_id=cluster_id, case_id=case_id,
        member_devices=member_devs, shared_entities=shared_ents,
        relationships=intra_rels, leads=leads)


@app.route("/clusters")
def clusters():
    case_id = request.args.get("case_id") or session.get("case_id","")
    if not case_id:
        return redirect(url_for("index"))
    db   = get_db()
    clusts = list(db.device_clusters.find(
        {"case_id": case_id}, {"_id": 0}).sort("device_count", -1))
    return render_template("clusters.html", clusters=clusts, case_id=case_id)


@app.route("/entity")
def entity_view():
    case_id = request.args.get("case_id") or session.get("case_id","")
    etype   = request.args.get("type","")
    evalue  = request.args.get("value","")
    db      = get_db()
    ent     = db.entity_network.find_one(
        {"case_id": case_id,
         "entity_value": {"$regex": re.escape(evalue), "$options":"i"}},
        {"_id": 0}) if evalue else None
    devices_raw = []
    if ent:
        devices_raw = list(db.devices.find(
            {"device_id": {"$in": ent.get("devices",[])}},
            {"_id": 0,"manifest_json":0}))
    infra = list(db.infrastructure_graph.find(
        {"case_id": case_id,
         "$or": [
            {"entity_a_val": {"$regex": re.escape(evalue),"$options":"i"}},
            {"entity_b_val": {"$regex": re.escape(evalue),"$options":"i"}},
         ]}, {"_id": 0}).limit(20)) if evalue else []
    rels = list(db.device_relationships.find(
        {"case_id": case_id,
         "device_a": {"$in": ent.get("devices",[]) if ent else []}},
        {"_id": 0}).sort("confidence_score",-1).limit(10)) if ent else []
    leads = list(db.investigative_leads.find(
        {"case_id": case_id,
         "devices": {"$in": ent.get("devices",[]) if ent else []}},
        {"_id": 0}).sort("confidence",-1).limit(6)) if ent else []
    return render_template("entity.html",
        case_id=case_id, entity=ent, entity_value=evalue,
        entity_type=etype, devices=devices_raw,
        infra_links=infra, relationships=rels, leads=leads)


@app.route("/leads")
def leads():
    case_id  = request.args.get("case_id") or session.get("case_id","")
    priority = request.args.get("priority","ALL")
    page     = int(request.args.get("page","1"))
    db       = get_db()
    filt     = {"case_id": case_id}
    if priority not in ("ALL",""):
        filt["priority"] = priority
    total    = db.investigative_leads.count_documents(filt)
    leads_list = list(db.investigative_leads.find(
        filt, {"_id": 0}).sort("confidence", -1)
        .skip((page-1)*PAGE_SIZE).limit(PAGE_SIZE))
    counts = {p: db.investigative_leads.count_documents(
        {"case_id": case_id, "priority": p})
        for p in ("HIGH","MEDIUM","LOW","INFORMATIONAL")}
    return render_template("leads.html",
        case_id=case_id, leads=leads_list, priority=priority,
        counts=counts, page=page,
        total_pages=max(1,(total+PAGE_SIZE-1)//PAGE_SIZE))


@app.route("/graph")
def graph():
    case_id = request.args.get("case_id") or session.get("case_id","")
    mode    = request.args.get("mode","relationships")
    device  = request.args.get("device_id","")
    return render_template("graph.html",
        case_id=case_id, mode=mode, device_filter=device)


@app.route("/timeline")
def timeline():
    case_id   = request.args.get("case_id") or session.get("case_id","")
    device_id = request.args.get("device_id","")
    from_ts   = request.args.get("from","")
    to_ts     = request.args.get("to","")
    db        = get_db()
    filt      = {"case_id": case_id}
    if device_id:
        filt["$or"] = [{"device_a": device_id}, {"device_b": device_id}]
    if from_ts:
        filt.setdefault("event_a.timestamp_utc", {})["$gte"] = from_ts
    events    = list(db.timeline_correlations.find(
        filt, {"_id": 0}).sort("delta_seconds", 1).limit(200))
    devices   = list(db.devices.find(
        {"case_id": case_id}, {"_id": 0, "manifest_json": 0}))
    return render_template("timeline.html",
        case_id=case_id, events=events, devices=devices,
        device_filter=device_id, from_ts=from_ts, to_ts=to_ts)


@app.route("/search")
def search():
    case_id = request.args.get("case_id") or session.get("case_id","")
    query   = request.args.get("q","").strip()
    return render_template("search.html", case_id=case_id, query=query)


@app.route("/ai")
def ai_page():
    case_id = request.args.get("case_id") or session.get("case_id","")
    db      = get_db()
    history = list(db.ai_analyses.find(
        {"case_id": case_id}, {"_id": 0, "raw_response": 0,
         "key_findings": 1, "summary": 1, "query": 1,
         "intent": 1, "created_at": 1, "analysis_id": 1}
    ).sort("created_at", -1).limit(20))
    recs    = list(db.ai_recommendations.find(
        {"case_id": case_id}, {"_id": 0}
    ).sort("created_at", -1).limit(10)) if hasattr(db, 'ai_recommendations') else []
    return render_template("ai.html", case_id=case_id,
                            ai_history=history, recommendations=recs,
                            has_ai=bool(HAS_HIVE_AI and NIM_API_KEY),
                            model=NIM_MODEL)


# ─────────────────────────────────────────────────────────────────────────────
# HTMX / API Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/search")
def api_search():
    """HTMX: returns a rendered HTML fragment of search results."""
    case_id = request.args.get("case_id","")
    q       = request.args.get("q","").strip()
    if not q or len(q) < 2:
        return "<p class='text-muted p-3'>Start typing to search…</p>"
    db      = get_db()
    # Entities
    ents = list(db.entity_network.find(
        {"case_id": case_id,
         "entity_value": {"$regex": re.escape(q), "$options":"i"}},
        {"_id": 0}).sort("significance",-1).limit(10))
    # Devices
    devs = list(db.devices.find(
        {"case_id": case_id,
         "$or": [{"device_id": {"$regex": re.escape(q),"$options":"i"}},
                  {"device_model":{"$regex": re.escape(q),"$options":"i"}}]},
        {"_id": 0,"manifest_json":0}).limit(10))
    # Clusters
    clusts = list(db.device_clusters.find(
        {"case_id": case_id,
         "$or": [{"cluster_id":   {"$regex": re.escape(q),"$options":"i"}},
                  {"cluster_type": {"$regex": re.escape(q),"$options":"i"}}]},
        {"_id": 0}).limit(5))
    # Leads
    leads_r = list(db.investigative_leads.find(
        {"case_id": case_id,
         "$or": [{"title":       {"$regex": re.escape(q),"$options":"i"}},
                  {"description": {"$regex": re.escape(q),"$options":"i"}}]},
        {"_id": 0}).sort("confidence",-1).limit(5))
    return render_template("fragments/search_results.html",
        query=q, case_id=case_id,
        entities=ents, devices=devs, clusters=clusts, leads=leads_r)


@app.route("/api/graph/data")
def api_graph_data():
    """Cytoscape.js element data (JSON)."""
    case_id = request.args.get("case_id","")
    mode    = request.args.get("mode","relationships")
    min_s   = float(request.args.get("min_score","0.0"))
    dev_f   = request.args.get("device_id","")
    db      = get_db()
    data    = build_graph_data(db, case_id, mode, dev_f, min_s)
    return jsonify(data)


@app.route("/api/ai/ask", methods=["POST"])
def api_ai_ask():
    """HTMX: invoke HIVE-AI and return rendered HTML fragment."""
    case_id  = request.form.get("case_id","")
    question = request.form.get("question","").strip()
    if not question:
        return "<div class='alert alert-warning mb-0'>Please enter a question.</div>"
    if not HAS_HIVE_AI or not NIM_API_KEY:
        return render_template("fragments/ai_message.html",
            question=question,
            summary="AI not configured — set NVIDIA_API_KEY.",
            error=True)
    try:
        ai = HIVEAI(case_id=case_id, api_key=NIM_API_KEY,
                     mongo_uri=MONGO_URI, mongo_db=MONGO_DB,
                     model=NIM_MODEL, use_mongo=True)
        analysis = ai.ask(question, stream=False)
        ai.close()
        return render_template("fragments/ai_message.html",
            question=question, analysis=analysis, error=False)
    except Exception as exc:
        app.logger.error(f"AI error: {exc}\n{traceback.format_exc()}")
        return render_template("fragments/ai_message.html",
            question=question,
            summary=f"Error: {exc}", error=True)


@app.route("/api/stats/<case_id>")
def api_stats(case_id: str):
    """JSON stats for a case."""
    db   = get_db()
    data = case_stats(db, case_id)
    return jsonify(data)


@app.route("/api/device/<device_id>/entities")
def api_device_entities(device_id: str):
    """HTMX: entity list for a device."""
    case_id = request.args.get("case_id","")
    db      = get_db()
    ents    = list(db.entity_network.find(
        {"case_id": case_id, "devices": device_id},
        {"_id": 0}).sort("significance",-1).limit(50))
    return render_template("fragments/entity_list.html",
        entities=ents, case_id=case_id, device_id=device_id)


@app.route("/api/leads/<case_id>")
def api_leads(case_id: str):
    """HTMX: top leads fragment."""
    db    = get_db()
    leads = list(db.investigative_leads.find(
        {"case_id": case_id}, {"_id": 0}).sort("confidence",-1).limit(5))
    return render_template("fragments/leads_mini.html",
        leads=leads, case_id=case_id)


@app.route("/api/ai/analysis/<analysis_id>")
def api_ai_analysis(analysis_id: str):
    """Full AI analysis detail (HTMX expand)."""
    db  = get_db()
    doc = db.ai_analyses.find_one(
        {"analysis_id": analysis_id}, {"_id": 0, "raw_response": 0})
    if not doc:
        return "<p class='text-danger'>Analysis not found.</p>"
    return render_template("fragments/ai_analysis_detail.html", analysis=doc)


# ─────────────────────────────────────────────────────────────────────────────
# Error Handlers
# ─────────────────────────────────────────────────────────────────────────────

@app.errorhandler(404)
def err_404(e):
    return render_template("error.html", code=404, msg=str(e)), 404

@app.errorhandler(503)
def err_503(e):
    return render_template("error.html", code=503,
        msg="MongoDB unavailable — ensure MongoDB is running."), 503

@app.errorhandler(Exception)
def err_generic(e):
    app.logger.error(traceback.format_exc())
    return render_template("error.html", code=500, msg=str(e)), 500


# ─────────────────────────────────────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="HIVE Command Center")
    p.add_argument("--host",  default="0.0.0.0")
    p.add_argument("--port",  type=int, default=5000)
    p.add_argument("--debug", action="store_true", default=DEBUG)
    a = p.parse_args()
    print(f"  HIVE Command Center  v1.0.0")
    print(f"  MongoDB : {MONGO_URI}/{MONGO_DB}")
    print(f"  AI      : {'enabled (' + NIM_MODEL.split('/')[-1] + ')' if NIM_API_KEY else 'disabled (no NVIDIA_API_KEY)'}")
    print(f"  URL     : http://{a.host}:{a.port}")
    app.run(host=a.host, port=a.port, debug=a.debug)
