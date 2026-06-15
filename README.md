# HIVE

### High-scale Investigation & Verification Engine

---

## Overview

**HIVE (High-scale Investigation & Verification Engine)** is a modular Digital Forensics, Incident Response (DFIR), and Criminal Intelligence platform designed to transform raw digital evidence into actionable investigative intelligence.

The platform automates the entire investigative lifecycle:

* Evidence Acquisition
* Artifact Parsing
* Entity Extraction
* Relationship Correlation
* Intelligence Generation
* AI-Assisted Analysis
* Investigator Workflows
* Interactive Intelligence Visualization

HIVE is designed around the principle that modern investigations often involve thousands of devices, millions of artifacts, and highly interconnected intelligence datasets that cannot be efficiently processed through traditional forensic workflows.

Rather than functioning as a single forensic tool, HIVE operates as a complete intelligence-processing ecosystem where each stage builds upon the previous one, progressively transforming raw evidence into investigator-ready intelligence.

---

## Project Information

This project was developed as part of the:

### Gurugram Police Cyber Security Internship (GPCSSI)

**Author:** Harsh Raj Singhania

The objective of HIVE is to explore how modern DFIR methodologies, intelligence analysis techniques, graph correlation, and AI-assisted investigation can be combined into a unified investigative platform.

This project is intended for educational, research, and authorized investigative environments only.

---

# Architecture

```text
                    HIVE Ecosystem

 ┌─────────────────────────────────────────────┐
 │              Stage 1: Collector             │
 │         Evidence Acquisition Engine         │
 └─────────────────┬───────────────────────────┘
                   │
                   ▼
 ┌─────────────────────────────────────────────┐
 │               Stage 2: Parser               │
 │      Universal Evidence Parsing Engine      │
 └─────────────────┬───────────────────────────┘
                   │
                   ▼
 ┌─────────────────────────────────────────────┐
 │             Stage 3: Correlator             │
 │      Intelligence Correlation Engine        │
 └─────────────────┬───────────────────────────┘
                   │
                   ▼
 ┌─────────────────────────────────────────────┐
 │            Stage 4: Investigator            │
 │         Investigation Query Engine          │
 └─────────────────┬───────────────────────────┘
                   │
                   ▼
 ┌─────────────────────────────────────────────┐
 │              Stage 5: HIVE-AI               │
 │   Investigative Intelligence Engine         │
 └─────────────────┬───────────────────────────┘
                   │
                   ▼
 ┌─────────────────────────────────────────────┐
 │       Stage 6: HIVE Command Center          │
 │      Unified Investigative Workspace        │
 └─────────────────────────────────────────────┘
```

---

# Stage 1 — Collector

### Core Acquisition Engine

The Collector is responsible for evidence acquisition from supported platforms.

### Supported Targets

* Android Devices
* Windows Systems
* Linux Systems
* Block Devices
* Forensic Images

### Capabilities

* Artifact collection
* Device triage
* Forensic imaging
* SHA-256 verification
* Chain of custody generation
* Metadata preservation

### Output

```text
Evidence Directory
 ├── Android Artifacts
 ├── Windows Artifacts
 ├── Linux Artifacts
 ├── Device Metadata
 └── Chain of Custody Records
```

---

# Stage 2 — Parser

### Universal Evidence Parser

The Parser transforms collected artifacts into structured intelligence.

### Extracted Intelligence

* Phone Numbers
* Email Addresses
* IPv4 / IPv6 Addresses
* Domains
* URLs
* Cryptocurrency Wallets
* Usernames
* Device Identifiers
* File Hashes
* Android Packages
* Wi-Fi Networks

### Timeline Reconstruction

Every timestamp-bearing artifact is normalized into a unified chronological timeline.

### Storage

```text
SQLite
└── hive_evidence.db
```

---

# Stage 3 — Correlator

### Intelligence Correlation Engine

The Correlator discovers relationships across evidence sources and devices.

### Features

* Cross-device correlation
* Relationship scoring
* Infrastructure mapping
* Cluster detection
* Timeline synchronization analysis
* Lead generation
* Criminal network identification

### Outputs

```text
MongoDB Collections

devices
entity_network
device_relationships
device_clusters
timeline_correlations
investigative_leads
infrastructure_graph
```

### Example

```text
Device A
 ├─ Email: target@example.com

Device B
 ├─ Email: target@example.com

Result:
Relationship Detected
Confidence Score Generated
```

---

# Stage 4 — Investigator

### Investigation Query Engine

The primary investigator interface for navigating intelligence.

### Capabilities

* Entity Search
* Device Profiling
* Timeline Reconstruction
* Cluster Analysis
* Relationship Exploration
* Infrastructure Investigation
* Lead Prioritization
* Report Generation

### Example Commands

```bash
search attacker@example.com

device DEV-001

timeline DEV-001

cluster CLUSTER-001

relationships

report full
```

---

# Stage 5 — HIVE-AI

### Investigative Intelligence Engine

Powered by:

* NVIDIA NIM
* Nemotron Super

HIVE-AI serves as an evidence-aware analytical assistant that helps investigators understand complex intelligence datasets.

### Design Principles

* Evidence-Bound Reasoning
* Confidence Scoring
* Traceable Findings
* Full Audit Trails
* Investigative Neutrality
* AI Transparency

### Supported Workflows

* Entity Analysis
* Device Analysis
* Cluster Analysis
* Timeline Reconstruction
* Infrastructure Mapping
* Risk Assessment
* Actor Attribution
* Target Prioritization
* Hypothesis Generation
* Intelligence Report Generation

### Example Queries

```text
Who are the operators?

Which devices appear linked?

What is the highest-risk cluster?

Explain the relationship between Device A and Device B.

Generate investigative hypotheses.
```

### Important

HIVE-AI is an analytical assistant only.

It does not replace investigators and should never be considered a legal source of truth.

---

# Stage 6 — HIVE Command Center (Under Development)

### Unified Investigative Workspace

The HIVE Command Center is the sixth and final stage of the HIVE ecosystem and serves as the centralized operational environment where investigators interact with all intelligence generated throughout the platform.

Built using:

* Flask
* Jinja2
* HTMX
* Bootstrap
* Cytoscape.js
* MongoDB

The Command Center unifies the outputs of every previous HIVE component into a single web-based investigative platform.

---

## Core Capabilities

### Case Management

Investigators begin from a case overview and progressively drill down into:

* Devices
* Entities
* Relationships
* Clusters
* Timelines
* Leads
* Reports
* AI Assessments

### Global Intelligence Search

Unified search across:

* Phone Numbers
* Emails
* Usernames
* Wallets
* Domains
* IP Addresses
* Device Identifiers
* Clusters
* Infrastructure

### Device Intelligence Profiles

Each device page contains:

* Timeline
* Relationships
* Associated Entities
* Cluster Memberships
* Investigative Leads
* AI Assessments

### Entity Exploration

Investigators can view how entities connect across:

* Devices
* Infrastructure
* Timelines
* Relationships

### Cluster Intelligence

Cluster pages provide:

* Dominant Entities
* Shared Infrastructure
* Relationship Strength
* Operational Patterns
* Investigative Findings

### Timeline Reconstruction

Cross-device chronological reconstruction of activity.

### Intelligence Graphs

Powered by Cytoscape.js.

Interactive exploration of:

* Devices
* Users
* Wallets
* Domains
* Emails
* Phone Numbers
* IP Addresses
* Applications

### HIVE-AI Integration

Investigators can:

* Ask natural language questions
* Generate intelligence reports
* Explain relationships
* Prioritize targets
* Generate hypotheses
* Reconstruct timelines

Every AI output remains linked to supporting evidence and audit records.

---

# Technology Stack

## Backend

* Python
* Flask
* MongoDB
* SQLite

## Frontend

* Bootstrap
* Jinja2
* HTMX
* Cytoscape.js

## AI

* NVIDIA NIM
* Nemotron Super

## Data Processing

* PyMongo
* Requests
* OpenAI-Compatible SDK
* NetworkX

---

# Quick Start

## Requirements

### System Requirements

* Python 3.10+
* MongoDB 7+
* Linux (recommended)
* NVIDIA NIM API Key (for HIVE-AI)

### Tested Platforms

* Kali Linux
* Ubuntu
* Debian
* Arch Linux

---

# Installation

## Clone Repository

```bash
git clone https://github.com/HarshRajSinghania/HIVE.git

cd HIVE
```

## Create Virtual Environment

```bash
python3 -m venv venv

source venv/bin/activate
```

## Install Dependencies

```bash
pip install pymongo
pip install requests
pip install openai
pip install networkx
```

Optional:

```bash
pip install python-evtx
pip install python-registry
```

---

# MongoDB Setup

## Ubuntu / Debian

```bash
sudo apt install mongodb
```

Start MongoDB:

```bash
sudo systemctl start mongodb

sudo systemctl enable mongodb
```

Verify:

```bash
mongosh
```

---

## Docker Setup

```bash
docker run -d \
  --name hive-mongo \
  -p 27017:27017 \
  mongo:latest
```

Verify:

```bash
docker ps
```

---

# NVIDIA NIM Setup

Create API Key:

1. Create NVIDIA Developer Account
2. Generate NIM API Key
3. Export Environment Variable

```bash
export NVIDIA_API_KEY="YOUR_API_KEY"
```

Optional:

```bash
export HIVE_AI_MODEL="nvidia/llama-3.3-nemotron-super-49b-v1"
```

Verify:

```bash
echo $NVIDIA_API_KEY
```

---

# Project Structure

```text
HIVE/

├── collector.py
├── parser.py
├── correlator.py
├── investigator.py
├── hive_ai.py
│
├── command_center/
│   ├── app.py
│   ├── templates/
│   ├── static/
│   └── routes/
│
├── evidence/
│
├── reports/
│
└── README.md
```

---

# Workflow

HIVE follows a strict pipeline.

```text
Collector
    ↓
Parser
    ↓
Correlator
    ↓
Investigator
    ↓
HIVE-AI
    ↓
Command Center
```

Each stage depends on outputs from the previous stage.

---

# Stage 1 Usage — Collector

## Android Acquisition

```bash
sudo python3 collector.py \
  --mode artifact \
  --target android \
  --serial ABC123
```

## Windows Acquisition

```bash
sudo python3 collector.py \
  --mode artifact \
  --target windows \
  --mount /mnt/windows
```

## Linux Acquisition

```bash
sudo python3 collector.py \
  --mode artifact \
  --target linux \
  --mount /mnt/linux
```

## Full Disk Imaging

```bash
sudo python3 collector.py \
  --mode image \
  --device /dev/sdb \
  --output /evidence
```

## Verify Image

```bash
python3 collector.py \
  --verify evidence.img
```

---

# Stage 2 Usage — Parser

## Parse Entire Case

```bash
python3 parser.py \
  --evidence ./evidence \
  --case-id CASE-001
```

## Parse Single Device

```bash
python3 parser.py \
  --device-dir ./android_device
```

## Export JSON

```bash
python3 parser.py \
  --evidence ./evidence \
  --case-id CASE-001 \
  --export-json
```

Output:

```text
hive_evidence.db
PARSER_REPORT.json
```

---

# Stage 3 Usage — Correlator

## Run Correlation

```bash
python3 correlator.py \
  --db hive_evidence.db \
  --case-id CASE-001
```

## Custom Sync Window

```bash
python3 correlator.py \
  --db hive_evidence.db \
  --case-id CASE-001 \
  --sync-window 60
```

Output stored in MongoDB:

```text
devices
entity_network
device_relationships
device_clusters
timeline_correlations
investigative_leads
```

---

# Stage 4 Usage — Investigator

## Launch Investigator Shell

```bash
python3 investigator.py \
  --db hive_evidence.db \
  --case-id CASE-001
```

### Search Entity

```text
search john@example.com
```

### Device Profile

```text
device DEV-001
```

### Compare Devices

```text
compare DEV-001 DEV-002
```

### Timeline

```text
timeline DEV-001
```

### List Clusters

```text
clusters
```

### Cluster Analysis

```text
cluster CLUSTER-001
```

### Leads

```text
leads
```

### Full Report

```text
report full
```

---

# Stage 5 Usage — HIVE-AI

## Interactive Mode

```bash
python3 hive_ai.py \
  --case-id CASE-001
```

### Example Questions

```text
Who are the likely operators?

Explain cluster CLUSTER-001.

Which devices appear to belong to the same actor?

What infrastructure appears shared?

Generate investigative hypotheses.
```

---

## Single Query

```bash
python3 hive_ai.py \
  --case-id CASE-001 \
  --ask "Who are the operators?"
```

---

## Cluster Analysis

```bash
python3 hive_ai.py \
  --case-id CASE-001 \
  --analyze cluster CLUSTER-001
```

---

## Generate Intelligence Brief

```bash
python3 hive_ai.py \
  --case-id CASE-001 \
  --brief \
  --output intelligence.md
```

---

# Stage 6 Usage — Command Center

⚠️ Under Active Development

Planned Launch:

```bash
python app.py
```

Default Address:

```text
http://localhost:5000
```

Planned Features:

* Case Dashboard
* Entity Search
* Device Profiles
* Intelligence Graphs
* Timeline Reconstruction
* AI Chat Interface
* Cluster Explorer
* Lead Management
* Report Generation
* Multi-Investigator Support

---

# Example End-to-End Investigation

```bash
# Acquire evidence
python collector.py

# Parse artifacts
python parser.py

# Correlate intelligence
python correlator.py

# Investigate
python investigator.py

# AI analysis
python hive_ai.py

# Web interface
python app.py
```

Result:

```text
Raw Evidence
    ↓
Structured Intelligence
    ↓
Relationships
    ↓
Investigative Leads
    ↓
AI Intelligence
    ↓
Interactive Investigation Platform
```


---

# Future Roadmap

* Multi-investigator collaboration
* RBAC and authentication
* Distributed processing workers
* Neo4j integration
* Elasticsearch integration
* Advanced graph analytics
* Real-time evidence ingestion
* Threat intelligence enrichment
* Automated case management
* AI-powered lead ranking

---

# Disclaimer

This project is intended for:

* Cybersecurity Research
* DFIR Education
* Authorized Investigations
* Academic Demonstration
* Security Training

Users are solely responsible for ensuring compliance with all applicable laws and regulations.

Unauthorized collection, processing, or analysis of data may violate local, national, or international laws.

---

# Acknowledgements

Developed by:

**Harsh Raj Singhania**

As part of the

**Gurugram Police Cyber Security Internship (GPCSSI)**

Special thanks to the mentors, officers, and coordinators of GPCSSI for providing the opportunity to explore large-scale DFIR, intelligence analysis, and AI-assisted investigative workflows.
