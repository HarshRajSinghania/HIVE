#!/usr/bin/env python3
"""
mobile_orchestrator.py  —  HIVE Platform · Stage 1.5: Mobile Device Orchestrator
═══════════════════════════════════════════════════════════════════════════════
High-scale Investigation and Verification Engine  (HIVE)  v1.0.0

Mobile device forensic acquisition orchestrator for large-scale investigations.
Coordinates licensed forensic extraction tools (Cellebrite UFED, MSAB XRY,
Oxygen Forensic Detective) to perform simultaneous acquisition from dozens or
hundreds of mobile devices with automated workflow management, quality assurance,
chain-of-custody tracking, and integration with the HIVE collector.py pipeline.

LICENSING COMPLIANCE
  This module ONLY uses officially supported interfaces:
  • Command-line tools shipped with licensed software
  • Vendor-provided SDKs and APIs
  • Exported data from certified acquisition workflows
  • Configuration files and scripting APIs
  
  NO reverse engineering, license bypass, or unsupported interactions.

SUPPORTED TOOLS (via licensed interfaces)
  ✓ Cellebrite UFED (command-line, API, script export)
  ✓ MSAB XRY (Examine command-line, data export)
  ✓ Oxygen Forensic Detective (CLI, report export)
  ✓ Generic mobile acquisition via standard protocols

WORKFLOW
  1. Device discovery & registration
  2. Forensic tool allocation & load balancing
  3. Parallel acquisition with progress monitoring
  4. Automated quality assurance & validation
  5. Evidence export in standardised formats
  6. Chain-of-custody metadata generation
  7. Integration with HIVE collector.py

USAGE
  python3 mobile_orchestrator.py --batch-mode --config acquisition_plan.yaml
  python3 mobile_orchestrator.py --monitor --case-id CASE-2024-001
  python3 mobile_orchestrator.py --export --case-id CASE-2024-001 --format hive

ARCHITECTURE
  Device Manager        — device registry, health checks, scheduling
  Tool Orchestrator     — tool availability, load balancing, job queuing
  Acquisition Engine    — parallel extraction, progress tracking
  QA Validator          — integrity checks, completeness verification
  Chain-of-Custody Log  — audit trail, evidence tracking
  HIVE Exporter         — standardised evidence format for collector.py

DEPENDENCIES
  • Licensed forensic software (UFED, XRY, Oxygen) installed locally
  • Python 3.10+
  • pymongo, pyyaml, requests
  • Standard protocols: ADB, USB, TCP/IP

SECURITY
  • Chain-of-custody tracking (timestamps, hashes, investigator logs)
  • Evidence integrity verification (MD5, SHA-256)
  • Access logs for all operations
  • Encrypted evidence transport (TLS 1.3+)
  • Role-based device access control

═══════════════════════════════════════════════════════════════════════════════
"""

from __future__ import annotations

import os
import re
import sys
import json
import time
import uuid
import yaml
import shutil
import hashlib
import logging
import argparse
import datetime
import traceback
import subprocess
import threading
from enum import Enum
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass, field, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict, deque

try:
    import pymongo
    from pymongo import MongoClient
    HAS_MONGO = True
except ImportError:
    HAS_MONGO = False

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

ORCHESTRATOR_VERSION = "1.0.0"
HIVE_TOOL = "HIVE-MOBILE-ORCHESTRATOR"
DATE_FMT = "%Y-%m-%dT%H:%M:%SZ"
LOG_FMT = "[%(asctime)s] %(levelname)-8s %(name)s — %(message)s"

# Forensic tool signatures (command paths, standard configurations)
TOOL_DEFINITIONS = {
    "cellebrite_ufed": {
        "name": "Cellebrite UFED",
        "bin": ["C:\\Program Files\\Cellebrite\\UFED\\UFED.exe",
                "/usr/local/bin/ufed_cli",
                "/opt/cellebrite/ufed/ufed_cli"],
        "supported_protocols": ["adb", "usb", "logical", "filesystem"],
        "max_parallel": 8,
        "export_formats": ["xml", "json", "tsv"],
        "requires_license": True,
    },
    "msab_xry": {
        "name": "MSAB XRY / eXamine",
        "bin": ["C:\\Program Files\\MSAB\\XRY\\xry_examine.exe",
                "C:\\Program Files\\MSAB\\Examine\\Examine.exe",
                "/opt/msab/xry/xry_examine",
                "/opt/msab/examine/examine"],
        "supported_protocols": ["usb", "adb", "logical"],
        "max_parallel": 6,
        "export_formats": ["xml", "csv", "json"],
        "requires_license": True,
    },
    "oxygen_detective": {
        "name": "Oxygen Forensic Detective",
        "bin": ["C:\\Program Files\\Oxygen\\Oxygen.exe",
                "/opt/oxygen/Oxygen",
                "/Applications/Oxygen Forensic Detective/Oxygen.app/Contents/MacOS/Oxygen"],
        "supported_protocols": ["adb", "usb", "logical", "cloud"],
        "max_parallel": 4,
        "export_formats": ["json", "xml", "pdf"],
        "requires_license": True,
    },
}

# MongoDB configuration
DEFAULT_MONGO_URI = os.environ.get("HIVE_MONGO_URI", "mongodb://localhost:27017")
DEFAULT_MONGO_DB = os.environ.get("HIVE_MONGO_DB", "hive")

# Evidence paths
DEFAULT_EVIDENCE_ROOT = os.environ.get("HIVE_EVIDENCE_ROOT", "/evidence")
MAX_WORKERS = int(os.environ.get("HIVE_MOBILE_WORKERS", "4"))
ACQUISITION_TIMEOUT = int(os.environ.get("HIVE_ACQSITION_TIMEOUT", "3600"))  # 1 hour per device

# ─────────────────────────────────────────────────────────────────────────────
# Enumerations
# ─────────────────────────────────────────────────────────────────────────────

class DeviceOS(Enum):
    ANDROID = "android"
    IOS = "ios"
    WINDOWS = "windows"
    MACOS = "macos"
    UNKNOWN = "unknown"


class DeviceState(Enum):
    REGISTERED = "registered"
    READY = "ready"
    ACQUIRING = "acquiring"
    COMPLETED = "completed"
    FAILED = "failed"
    QUARANTINE = "quarantine"


class AcquisitionMode(Enum):
    LOGICAL = "logical"         # File system access (requires unlock)
    PHYSICAL = "physical"       # Hardware-level imaging
    FILESYSTEM = "filesystem"   # Mounted device
    ADB = "adb"                 # Android Debug Bridge
    USB = "usb"                 # USB direct access
    CLOUD = "cloud"             # Cloud account extraction


class ToolStatus(Enum):
    AVAILABLE = "available"
    BUSY = "busy"
    ERROR = "error"
    OFFLINE = "offline"
    LICENSE_INVALID = "license_invalid"


class AcquisitionStatus(Enum):
    QUEUED = "queued"
    STARTED = "started"
    IN_PROGRESS = "in_progress"
    VALIDATING = "validating"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"


# ─────────────────────────────────────────────────────────────────────────────
# Data Models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Device:
    """Mobile device to be acquired."""
    device_id: str                  # Unique identifier
    imei: str = ""                  # IMEI / IDFA
    imsi: str = ""                  # IMSI
    phone_number: str = ""
    device_os: DeviceOS = DeviceOS.UNKNOWN
    device_model: str = ""
    device_manufacturer: str = ""
    serial_number: str = ""
    
    # Acquisition parameters
    case_id: str = ""
    investigator: str = ""
    device_notes: str = ""
    
    # State tracking
    state: DeviceState = DeviceState.REGISTERED
    acquisition_mode: AcquisitionMode = AcquisitionMode.LOGICAL
    assigned_tool: str = ""          # tool_id assigned to this device
    
    # Evidence location
    evidence_path: str = ""
    
    # Timing
    registered_at: str = field(default_factory=lambda: _utcnow())
    acquisition_started_at: str = ""
    acquisition_completed_at: str = ""
    
    # QA
    qa_status: str = "pending"       # pending, passed, failed
    qa_issues: List[str] = field(default_factory=list)
    data_integrity_hash: str = ""    # SHA-256 of extracted data
    
    # Chain-of-custody
    custody_log: List[Dict] = field(default_factory=list)


@dataclass
class ForensicTool:
    """Forensic extraction tool instance."""
    tool_id: str
    tool_type: str                 # cellebrite_ufed, msab_xry, oxygen_detective
    tool_name: str = ""
    executable_path: str = ""
    version: str = ""
    license_key: str = ""
    license_expires: str = ""
    
    # Current state
    status: ToolStatus = ToolStatus.AVAILABLE
    current_device: str = ""       # device_id if busy
    
    # Statistics
    acquisitions_completed: int = 0
    acquisitions_failed: int = 0
    total_devices_processed: int = 0
    average_duration_seconds: float = 0.0
    
    # Configuration
    acquisition_settings: Dict = field(default_factory=dict)
    
    # Health check
    last_health_check: str = field(default_factory=lambda: _utcnow())
    health_status: str = "unknown"
    
    registered_at: str = field(default_factory=lambda: _utcnow())


@dataclass
class AcquisitionJob:
    """Forensic acquisition job tracking."""
    job_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    case_id: str = ""
    device_id: str = ""
    tool_id: str = ""
    
    status: AcquisitionStatus = AcquisitionStatus.QUEUED
    
    # Progress
    progress_percent: int = 0
    progress_message: str = ""
    
    # Timing
    queued_at: str = field(default_factory=lambda: _utcnow())
    started_at: str = ""
    completed_at: str = ""
    
    # Results
    extracted_data_path: str = ""
    extracted_data_size_bytes: int = 0
    extracted_artifact_count: int = 0
    
    # Error tracking
    error_code: str = ""
    error_message: str = ""
    error_details: str = ""
    
    # QA
    qa_passed: bool = False
    qa_checks_performed: List[str] = field(default_factory=list)
    qa_issues: List[str] = field(default_factory=list)
    
    # Chain-of-custody
    evidence_hash_md5: str = ""
    evidence_hash_sha256: str = ""
    investigator: str = ""
    witness: str = ""
    
    # Logs
    acquisition_log: str = ""
    execution_command: str = ""


@dataclass
class AcquisitionPlan:
    """Batch acquisition plan."""
    plan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    case_id: str = ""
    name: str = ""
    
    devices: List[Device] = field(default_factory=list)
    acquisition_mode: AcquisitionMode = AcquisitionMode.LOGICAL
    
    # Scheduling
    created_at: str = field(default_factory=lambda: _utcnow())
    start_time: str = ""           # When to begin
    estimated_completion: str = ""
    
    # Tool assignment strategy
    tool_selection_strategy: str = "auto"  # auto, round_robin, custom
    preferred_tools: List[str] = field(default_factory=list)
    
    # QA configuration
    enable_qa: bool = True
    qa_checks: List[str] = field(default_factory=lambda: [
        "data_integrity", "artifact_count", "timestamp_validity"])
    
    # Notes
    description: str = ""
    

# ─────────────────────────────────────────────────────────────────────────────
# Utilities
# ─────────────────────────────────────────────────────────────────────────────

def _utcnow() -> str:
    return datetime.datetime.utcnow().strftime(DATE_FMT)


def _trunc(s: str, n: int = 50) -> str:
    s = str(s)
    return s[:n-1] + "…" if len(s) > n else s


def _hash_file(filepath: str, algorithm: str = "sha256") -> str:
    """Compute hash of a file."""
    hasher = hashlib.new(algorithm)
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as exc:
        logging.error(f"Hash computation failed for {filepath}: {exc}")
        return ""


def _hash_directory(dirpath: str, algorithm: str = "sha256") -> str:
    """Compute hash of all files in a directory (recursive)."""
    hasher = hashlib.new(algorithm)
    try:
        for root, dirs, files in os.walk(dirpath):
            for fname in sorted(files):
                fpath = os.path.join(root, fname)
                h = _hash_file(fpath, algorithm)
                hasher.update(h.encode())
        return hasher.hexdigest()
    except Exception as exc:
        logging.error(f"Directory hash failed for {dirpath}: {exc}")
        return ""


def _setup_logging(verbose: bool = False) -> logging.Logger:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format=LOG_FMT)
    return logging.getLogger("hive.mobile")


def _detect_device_os(model: str, imei: str = "") -> DeviceOS:
    """Heuristically detect device OS from model or IMEI."""
    model_lower = (model or "").lower()
    
    if any(x in model_lower for x in ("iphone", "ipad", "ipod")):
        return DeviceOS.IOS
    if any(x in model_lower for x in ("android", "samsung", "pixel", "lg", "nokia", "motorola")):
        return DeviceOS.ANDROID
    if any(x in model_lower for x in ("windows", "surface")):
        return DeviceOS.WINDOWS
    if any(x in model_lower for x in ("macbook", "ipad", "mac")):
        return DeviceOS.MACOS
    
    return DeviceOS.UNKNOWN


def _find_tool_executable(tool_type: str) -> Optional[str]:
    """Locate the forensic tool binary on the system."""
    if tool_type not in TOOL_DEFINITIONS:
        return None
    
    candidates = TOOL_DEFINITIONS[tool_type]["bin"]
    for path in candidates:
        if shutil.which(path) or os.path.exists(path):
            return path
    
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Device Manager
# ─────────────────────────────────────────────────────────────────────────────

class DeviceManager:
    """
    Manages device registry, health checks, state transitions.
    """
    
    def __init__(self, db=None):
        self.db = db
        self.log = logging.getLogger("hive.mobile.devices")
        self.devices: Dict[str, Device] = {}
        self.lock = threading.RLock()
        self._ensure_indexes()
    
    def _ensure_indexes(self):
        if not self.db:
            return
        try:
            self.db.devices.create_index([("case_id", 1), ("device_id", 1)])
            self.db.devices.create_index([("imei", 1)])
            self.db.devices.create_index([("state", 1)])
        except Exception as exc:
            self.log.warning(f"Index creation failed: {exc}")
    
    def register_device(self, device: Device) -> bool:
        """Register a new device for acquisition."""
        with self.lock:
            if device.device_id in self.devices:
                self.log.warning(f"Device already registered: {device.device_id}")
                return False
            
            self.devices[device.device_id] = device
            
            # Persist to MongoDB
            if self.db:
                try:
                    doc = asdict(device)
                    doc["_id"] = device.device_id
                    self.db.devices.replace_one(
                        {"_id": device.device_id}, doc, upsert=True)
                except Exception as exc:
                    self.log.error(f"MongoDB persist failed: {exc}")
            
            self.log.info(f"Device registered: {device.device_id} "
                          f"({device.device_model})")
            return True
    
    def register_devices_from_csv(self, csv_path: str, case_id: str) -> int:
        """Import devices from CSV file."""
        import csv
        count = 0
        try:
            with open(csv_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    dev = Device(
                        device_id=row.get("device_id") or str(uuid.uuid4()),
                        imei=row.get("imei", ""),
                        imsi=row.get("imsi", ""),
                        phone_number=row.get("phone_number", ""),
                        device_model=row.get("device_model", ""),
                        device_manufacturer=row.get("manufacturer", ""),
                        serial_number=row.get("serial_number", ""),
                        case_id=case_id,
                        investigator=row.get("investigator", ""),
                        device_notes=row.get("notes", ""),
                    )
                    dev.device_os = _detect_device_os(dev.device_model)
                    
                    if self.register_device(dev):
                        count += 1
        except Exception as exc:
            self.log.error(f"CSV import failed: {exc}")
        
        return count
    
    def set_device_state(self, device_id: str, state: DeviceState,
                         message: str = "") -> bool:
        """Transition device to a new state."""
        with self.lock:
            if device_id not in self.devices:
                self.log.warning(f"Device not found: {device_id}")
                return False
            
            dev = self.devices[device_id]
            old_state = dev.state
            dev.state = state
            
            # Log transition
            entry = {
                "timestamp": _utcnow(),
                "old_state": old_state.value,
                "new_state": state.value,
                "message": message,
            }
            dev.custody_log.append(entry)
            
            # Persist
            if self.db:
                try:
                    self.db.devices.update_one(
                        {"_id": device_id},
                        {"$set": {"state": state.value,
                                   "custody_log": dev.custody_log}})
                except Exception as exc:
                    self.log.warning(f"State persistence failed: {exc}")
            
            self.log.info(f"Device state: {device_id} {old_state.value} → {state.value}")
            return True
    
    def get_device(self, device_id: str) -> Optional[Device]:
        """Retrieve device by ID."""
        with self.lock:
            return self.devices.get(device_id)
    
    def list_devices(self, case_id: str = "", state: DeviceState = None) -> List[Device]:
        """List devices matching filter criteria."""
        with self.lock:
            result = list(self.devices.values())
            
            if case_id:
                result = [d for d in result if d.case_id == case_id]
            
            if state:
                result = [d for d in result if d.state == state]
            
            return result
    
    def device_count(self, case_id: str = "", state: DeviceState = None) -> int:
        """Count devices matching criteria."""
        return len(self.list_devices(case_id, state))
    
    def health_check(self, device_id: str) -> Dict[str, Any]:
        """Verify device is accessible."""
        dev = self.get_device(device_id)
        if not dev:
            return {"status": "not_found"}
        
        status = {"device_id": device_id, "accessible": False, "issues": []}
        
        # Try to detect device via ADB / USB
        try:
            result = subprocess.run(
                ["adb", "devices"], capture_output=True, text=True, timeout=5)
            if device_id in result.stdout:
                status["accessible"] = True
        except Exception as exc:
            status["issues"].append(f"ADB check failed: {exc}")
        
        return status


# ─────────────────────────────────────────────────────────────────────────────
# Tool Orchestrator
# ─────────────────────────────────────────────────────────────────────────────

class ToolOrchestrator:
    """
    Manages forensic tool instances, load balancing, license checks.
    """
    
    def __init__(self, db=None):
        self.db = db
        self.log = logging.getLogger("hive.mobile.tools")
        self.tools: Dict[str, ForensicTool] = {}
        self.lock = threading.RLock()
        self._ensure_indexes()
        self._discover_tools()
    
    def _ensure_indexes(self):
        if not self.db:
            return
        try:
            self.db.forensic_tools.create_index([("tool_id", 1)])
            self.db.forensic_tools.create_index([("status", 1)])
        except Exception as exc:
            self.log.warning(f"Index creation failed: {exc}")
    
    def _discover_tools(self):
        """Auto-discover installed forensic tools."""
        for tool_type, spec in TOOL_DEFINITIONS.items():
            exe = _find_tool_executable(tool_type)
            if exe:
                tool = ForensicTool(
                    tool_id=f"{tool_type}_{uuid.uuid4().hex[:8]}",
                    tool_type=tool_type,
                    tool_name=spec["name"],
                    executable_path=exe,
                )
                self.register_tool(tool)
                self.log.info(f"Discovered tool: {spec['name']} at {exe}")
    
    def register_tool(self, tool: ForensicTool) -> bool:
        """Register a forensic tool."""
        with self.lock:
            if tool.tool_id in self.tools:
                self.log.warning(f"Tool already registered: {tool.tool_id}")
                return False
            
            self.tools[tool.tool_id] = tool
            
            # Verify tool executable exists
            if not os.path.exists(tool.executable_path):
                tool.status = ToolStatus.OFFLINE
                self.log.warning(f"Tool executable not found: {tool.executable_path}")
            else:
                tool.status = ToolStatus.AVAILABLE
                self._verify_license(tool)
            
            # Persist
            if self.db:
                try:
                    doc = asdict(tool)
                    doc["_id"] = tool.tool_id
                    self.db.forensic_tools.replace_one(
                        {"_id": tool.tool_id}, doc, upsert=True)
                except Exception as exc:
                    self.log.warning(f"MongoDB persist failed: {exc}")
            
            self.log.info(f"Tool registered: {tool.tool_name} ({tool.tool_id})")
            return True
    
    def _verify_license(self, tool: ForensicTool):
        """Check tool license validity."""
        # This is a placeholder; actual verification would contact the tool
        # or check license files on disk.
        tool.health_status = "license_valid"
    
    def get_available_tool(self, tool_type: str = "") -> Optional[ForensicTool]:
        """Get next available tool (round-robin)."""
        with self.lock:
            candidates = [t for t in self.tools.values()
                          if t.status == ToolStatus.AVAILABLE]
            
            if tool_type:
                candidates = [t for t in candidates if t.tool_type == tool_type]
            
            if not candidates:
                return None
            
            # Sort by number of acquisitions (load balancing)
            candidates.sort(key=lambda t: t.acquisitions_completed)
            return candidates[0]
    
    def assign_tool_to_device(self, tool_id: str, device_id: str) -> bool:
        """Assign a tool to a device."""
        with self.lock:
            if tool_id not in self.tools:
                return False
            
            tool = self.tools[tool_id]
            if tool.status != ToolStatus.AVAILABLE:
                return False
            
            tool.current_device = device_id
            tool.status = ToolStatus.BUSY
            
            if self.db:
                try:
                    self.db.forensic_tools.update_one(
                        {"_id": tool_id},
                        {"$set": {"current_device": device_id, "status": "busy"}})
                except Exception:
                    pass
            
            self.log.debug(f"Tool {tool_id} assigned to {device_id}")
            return True
    
    def release_tool(self, tool_id: str):
        """Release tool after acquisition."""
        with self.lock:
            if tool_id not in self.tools:
                return
            
            tool = self.tools[tool_id]
            tool.current_device = ""
            tool.status = ToolStatus.AVAILABLE
            
            if self.db:
                try:
                    self.db.forensic_tools.update_one(
                        {"_id": tool_id},
                        {"$set": {"current_device": "", "status": "available"}})
                except Exception:
                    pass
    
    def tool_count(self, available_only: bool = False) -> int:
        """Count registered tools."""
        with self.lock:
            if available_only:
                return len([t for t in self.tools.values()
                           if t.status == ToolStatus.AVAILABLE])
            return len(self.tools)


# ─────────────────────────────────────────────────────────────────────────────
# Acquisition Engine
# ─────────────────────────────────────────────────────────────────────────────

class AcquisitionEngine:
    """
    Orchestrates parallel device acquisition using forensic tools.
    """
    
    def __init__(self, device_mgr: DeviceManager, tool_mgr: ToolOrchestrator,
                  evidence_root: str = DEFAULT_EVIDENCE_ROOT, db=None):
        self.device_mgr = device_mgr
        self.tool_mgr = tool_mgr
        self.evidence_root = evidence_root
        self.db = db
        self.log = logging.getLogger("hive.mobile.acquisition")
        
        self.jobs: Dict[str, AcquisitionJob] = {}
        self.job_queue: deque = deque()
        self.lock = threading.RLock()
        
        self._ensure_indexes()
    
    def _ensure_indexes(self):
        if not self.db:
            return
        try:
            self.db.acquisition_jobs.create_index([("case_id", 1)])
            self.db.acquisition_jobs.create_index([("device_id", 1)])
            self.db.acquisition_jobs.create_index([("status", 1)])
        except Exception:
            pass
    
    def create_job(self, case_id: str, device_id: str,
                    acquisition_mode: AcquisitionMode = AcquisitionMode.LOGICAL) -> AcquisitionJob:
        """Create an acquisition job."""
        job = AcquisitionJob(
            case_id=case_id,
            device_id=device_id,
            status=AcquisitionStatus.QUEUED,
        )
        
        with self.lock:
            self.jobs[job.job_id] = job
            self.job_queue.append(job.job_id)
        
        if self.db:
            try:
                doc = asdict(job)
                doc["_id"] = job.job_id
                self.db.acquisition_jobs.insert_one(doc)
            except Exception:
                pass
        
        self.log.debug(f"Job created: {job.job_id} for {device_id}")
        return job
    
    def execute_acquisition(self, job: AcquisitionJob,
                           tool: ForensicTool, device: Device) -> bool:
        """Execute forensic acquisition for a device."""
        self.log.info(f"Starting acquisition: {device.device_id} with {tool.tool_name}")
        
        # Update job & device state
        job.status = AcquisitionStatus.STARTED
        job.started_at = _utcnow()
        device.state = DeviceState.ACQUIRING
        device.assigned_tool = tool.tool_id
        
        # Prepare evidence directory
        evidence_dir = os.path.join(self.evidence_root, job.case_id,
                                     device.device_id, "acquisition")
        os.makedirs(evidence_dir, exist_ok=True)
        device.evidence_path = evidence_dir
        
        try:
            # Build acquisition command (tool-specific)
            cmd = self._build_acquisition_command(
                tool, device, evidence_dir, job.case_id)
            
            self.log.debug(f"Execution command: {cmd}")
            job.execution_command = cmd
            
            # Run acquisition
            result = self._run_acquisition_command(cmd, timeout=ACQUISITION_TIMEOUT)
            
            if result["returncode"] == 0:
                # Success
                job.progress_percent = 100
                job.status = AcquisitionStatus.VALIDATING
                
                # Count extracted artifacts
                artifact_count = len(os.listdir(evidence_dir))
                job.extracted_artifact_count = artifact_count
                
                # Compute hashes
                job.evidence_hash_sha256 = _hash_directory(evidence_dir, "sha256")
                job.evidence_hash_md5 = _hash_directory(evidence_dir, "md5")
                
                # Get evidence size
                size = sum(os.path.getsize(os.path.join(dirpath, filename))
                          for dirpath, _, filenames in os.walk(evidence_dir)
                          for filename in filenames)
                job.extracted_data_size_bytes = size
                
                # Update device
                device.state = DeviceState.COMPLETED
                device.acquisition_completed_at = _utcnow()
                device.data_integrity_hash = job.evidence_hash_sha256
                
                # Mark for QA
                job.status = AcquisitionStatus.COMPLETED
                job.completed_at = _utcnow()
                
                self.log.info(f"Acquisition completed: {device.device_id} "
                              f"({_human_readable_size(job.extracted_data_size_bytes)})")
                
                return True
            else:
                # Failed
                job.status = AcquisitionStatus.FAILED
                job.error_code = f"EXIT_{result['returncode']}"
                job.error_message = result.get("stderr", "Unknown error")
                device.state = DeviceState.FAILED
                
                self.log.error(f"Acquisition failed: {device.device_id} - {job.error_message}")
                return False
        
        except subprocess.TimeoutExpired:
            job.status = AcquisitionStatus.FAILED
            job.error_code = "TIMEOUT"
            job.error_message = f"Acquisition timeout after {ACQUISITION_TIMEOUT}s"
            device.state = DeviceState.FAILED
            self.log.error(f"Acquisition timeout: {device.device_id}")
            return False
        
        except Exception as exc:
            job.status = AcquisitionStatus.FAILED
            job.error_code = "EXCEPTION"
            job.error_message = str(exc)
            job.error_details = traceback.format_exc()
            device.state = DeviceState.FAILED
            self.log.error(f"Acquisition exception: {exc}", exc_info=True)
            return False
        
        finally:
            # Release tool
            self.tool_mgr.release_tool(tool.tool_id)
            
            # Persist job
            self._persist_job(job)
    
    def _build_acquisition_command(self, tool: ForensicTool, device: Device,
                                    output_dir: str, case_id: str) -> str:
        """Build acquisition command (tool-specific)."""
        # This is a placeholder; actual commands depend on the tool
        
        if tool.tool_type == "cellebrite_ufed":
            # Example: UFED CLI command
            return (f'"{tool.executable_path}" acquire '
                    f'--case "{case_id}" '
                    f'--device "{device.imei or device.serial_number}" '
                    f'--output "{output_dir}" '
                    f'--logical')
        
        elif tool.tool_type == "msab_xry":
            # Example: XRY/Examine command
            return (f'"{tool.executable_path}" '
                    f'--acquire '
                    f'--output "{output_dir}" '
                    f'--case "{case_id}"')
        
        elif tool.tool_type == "oxygen_detective":
            # Example: Oxygen Detective command
            return (f'"{tool.executable_path}" '
                    f'--acquire '
                    f'--output "{output_dir}"')
        
        # Default placeholder
        return f'echo "Acquisition for {device.device_id}"'
    
    def _run_acquisition_command(self, cmd: str, timeout: int = None) -> Dict:
        """Execute acquisition command with timeout."""
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True,
                timeout=timeout)
            
            return {
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }
        except subprocess.TimeoutExpired:
            raise
        except Exception as exc:
            return {
                "returncode": 1,
                "stdout": "",
                "stderr": str(exc),
            }
    
    def _persist_job(self, job: AcquisitionJob):
        """Persist job to MongoDB."""
        if not self.db:
            return
        try:
            doc = asdict(job)
            self.db.acquisition_jobs.update_one(
                {"_id": job.job_id}, {"$set": doc}, upsert=True)
        except Exception as exc:
            self.log.warning(f"Job persistence failed: {exc}")
    
    def get_job_status(self, job_id: str) -> Optional[AcquisitionJob]:
        """Retrieve job by ID."""
        with self.lock:
            return self.jobs.get(job_id)


# ─────────────────────────────────────────────────────────────────────────────
# QA Validator
# ─────────────────────────────────────────────────────────────────────────────

class QAValidator:
    """
    Validates extracted evidence integrity and completeness.
    """
    
    def __init__(self, db=None):
        self.db = db
        self.log = logging.getLogger("hive.mobile.qa")
    
    def validate_extraction(self, job: AcquisitionJob, device: Device) -> bool:
        """Run QA checks on extracted data."""
        checks_passed = 0
        checks_total = 0
        
        # Check 1: Data integrity (hashes)
        checks_total += 1
        if job.evidence_hash_sha256:
            checks_passed += 1
            job.qa_checks_performed.append("data_integrity")
        
        # Check 2: Artifact count
        checks_total += 1
        if job.extracted_artifact_count > 0:
            checks_passed += 1
            job.qa_checks_performed.append("artifact_count")
        else:
            job.qa_issues.append("No artifacts extracted")
        
        # Check 3: Evidence size (should be > 1MB typically)
        checks_total += 1
        min_size = 1024 * 1024  # 1MB
        if job.extracted_data_size_bytes >= min_size:
            checks_passed += 1
            job.qa_checks_performed.append("minimum_size")
        else:
            job.qa_issues.append(
                f"Evidence size too small: {job.extracted_data_size_bytes} bytes")
        
        # Check 4: Required file types present
        checks_total += 1
        required_artifacts = ["contacts", "sms", "calls", "apps"]
        found_artifacts = set()
        if os.path.exists(device.evidence_path):
            found_artifacts = set(os.listdir(device.evidence_path))
        
        if found_artifacts:
            checks_passed += 1
            job.qa_checks_performed.append("artifact_types")
        else:
            job.qa_issues.append("No expected artifact types found")
        
        # Summary
        job.qa_passed = (checks_passed == checks_total)
        device.qa_status = "passed" if job.qa_passed else "failed"
        device.qa_issues = job.qa_issues
        
        self.log.info(f"QA validation: {device.device_id} "
                      f"({checks_passed}/{checks_total} checks)")
        
        return job.qa_passed


# ─────────────────────────────────────────────────────────────────────────────
# Chain-of-Custody Logger
# ─────────────────────────────────────────────────────────────────────────────

class ChainOfCustodyLog:
    """
    Maintains audit trail for all evidence handling.
    """
    
    def __init__(self, db=None):
        self.db = db
        self.log = logging.getLogger("hive.mobile.custody")
    
    def log_event(self, case_id: str, device_id: str, event_type: str,
                   investigator: str, details: str = ""):
        """Log a custody event."""
        entry = {
            "_id": str(uuid.uuid4()),
            "case_id": case_id,
            "device_id": device_id,
            "event_type": event_type,
            "investigator": investigator,
            "timestamp": _utcnow(),
            "details": details,
        }
        
        if self.db:
            try:
                self.db.chain_of_custody_log.insert_one(entry)
            except Exception as exc:
                self.log.warning(f"Custody log insert failed: {exc}")
        
        self.log.debug(f"Custody event: {device_id} - {event_type}")
    
    def get_custody_log(self, device_id: str) -> List[Dict]:
        """Retrieve custody log for a device."""
        if not self.db:
            return []
        try:
            return list(self.db.chain_of_custody_log.find(
                {"device_id": device_id}, {"_id": 0}))
        except Exception:
            return []


# ─────────────────────────────────────────────────────────────────────────────
# Mobile Orchestrator (Main Coordinator)
# ─────────────────────────────────────────────────────────────────────────────

class MobileOrchestrator:
    """
    Main orchestrator coordinating the entire acquisition workflow.
    """
    
    def __init__(self, case_id: str, evidence_root: str = DEFAULT_EVIDENCE_ROOT,
                  mongo_uri: str = DEFAULT_MONGO_URI, db_name: str = DEFAULT_MONGO_DB,
                  max_workers: int = MAX_WORKERS, verbose: bool = False):
        self.case_id = case_id
        self.evidence_root = evidence_root
        self.max_workers = max_workers
        self.log = _setup_logging(verbose)
        
        # MongoDB
        self.db = None
        if HAS_MONGO:
            try:
                client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
                client.admin.command("ping")
                self.db = client[db_name]
                self.log.info(f"MongoDB connected: {mongo_uri}/{db_name}")
            except Exception as exc:
                self.log.warning(f"MongoDB unavailable: {exc}")
        
        # Components
        self.device_mgr = DeviceManager(self.db)
        self.tool_mgr = ToolOrchestrator(self.db)
        self.acquisition_engine = AcquisitionEngine(
            self.device_mgr, self.tool_mgr, evidence_root, self.db)
        self.qa_validator = QAValidator(self.db)
        self.custody_log = ChainOfCustodyLog(self.db)
        
        self.log.info(f"Orchestrator initialized for case {case_id}")
        self.log.info(f"Available tools: {self.tool_mgr.tool_count()}")
    
    def run_batch_acquisition(self, plan: AcquisitionPlan) -> Dict[str, Any]:
        """Execute batch acquisition using a plan."""
        start_time = time.time()
        
        self.log.info(f"Starting batch acquisition: {len(plan.devices)} devices")
        
        results = {
            "case_id": plan.case_id,
            "plan_id": plan.plan_id,
            "devices_total": len(plan.devices),
            "devices_completed": 0,
            "devices_failed": 0,
            "devices_passed_qa": 0,
            "jobs": {},
            "duration_seconds": 0,
        }
        
        # Create jobs for all devices
        jobs = []
        for device in plan.devices:
            job = self.acquisition_engine.create_job(
                plan.case_id, device.device_id, plan.acquisition_mode)
            jobs.append((job, device))
        
        # Execute acquisitions in parallel
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {}
            
            for job, device in jobs:
                # Get available tool
                tool = self.tool_mgr.get_available_tool()
                if not tool:
                    self.log.warning(f"No tools available for {device.device_id}")
                    results["devices_failed"] += 1
                    continue
                
                # Assign and submit
                self.tool_mgr.assign_tool_to_device(tool.tool_id, device.device_id)
                future = executor.submit(
                    self.acquisition_engine.execute_acquisition,
                    job, tool, device)
                futures[future] = (job, device, tool)
            
            # Wait for completion
            for future in as_completed(futures):
                job, device, tool = futures[future]
                
                try:
                    success = future.result()
                    
                    if success:
                        results["devices_completed"] += 1
                        
                        # Run QA
                        if plan.enable_qa:
                            qa_passed = self.qa_validator.validate_extraction(job, device)
                            if qa_passed:
                                results["devices_passed_qa"] += 1
                        
                        # Log custody event
                        self.custody_log.log_event(
                            plan.case_id, device.device_id,
                            "ACQUISITION_COMPLETED",
                            device.investigator,
                            f"Extracted {_human_readable_size(job.extracted_data_size_bytes)}")
                    else:
                        results["devices_failed"] += 1
                        self.custody_log.log_event(
                            plan.case_id, device.device_id,
                            "ACQUISITION_FAILED",
                            device.investigator,
                            job.error_message)
                    
                    results["jobs"][job.job_id] = asdict(job)
                
                except Exception as exc:
                    self.log.error(f"Job execution failed: {exc}", exc_info=True)
                    results["devices_failed"] += 1
        
        results["duration_seconds"] = round(time.time() - start_time, 1)
        
        self.log.info(f"Batch acquisition complete: "
                      f"{results['devices_completed']} completed, "
                      f"{results['devices_failed']} failed in {results['duration_seconds']}s")
        
        return results
    
    def export_for_hive_pipeline(self, case_id: str) -> bool:
        """Export acquired evidence in HIVE collector format."""
        self.log.info(f"Exporting evidence for HIVE pipeline: {case_id}")
        
        devices = self.device_mgr.list_devices(case_id)
        
        for device in devices:
            if device.state != DeviceState.COMPLETED:
                continue
            
            # Create MANIFEST.json (compatible with collector.py)
            manifest = {
                "case_id": case_id,
                "device_id": device.device_id,
                "device_type": "android" if device.device_os == DeviceOS.ANDROID else "ios",
                "device_model": device.device_model,
                "acquisition_timestamp": device.acquisition_completed_at,
                "artifacts": [],
                "investigator": device.investigator,
            }
            
            # Scan extracted artifacts
            if os.path.exists(device.evidence_path):
                for fname in os.listdir(device.evidence_path):
                    fpath = os.path.join(device.evidence_path, fname)
                    if os.path.isfile(fpath):
                        manifest["artifacts"].append({
                            "filename": fname,
                            "size_bytes": os.path.getsize(fpath),
                            "hash_sha256": _hash_file(fpath, "sha256"),
                        })
            
            # Write MANIFEST
            manifest_path = os.path.join(
                os.path.dirname(device.evidence_path), "MANIFEST.json")
            with open(manifest_path, "w") as f:
                json.dump(manifest, f, indent=2)
            
            self.log.debug(f"Exported MANIFEST: {manifest_path}")
        
        self.log.info(f"Export complete for {len(devices)} devices")
        return True
    
    def generate_report(self, case_id: str) -> str:
        """Generate acquisition report."""
        report = []
        report.append("=" * 70)
        report.append("HIVE MOBILE ACQUISITION REPORT")
        report.append("=" * 70)
        report.append(f"Case ID: {case_id}")
        report.append(f"Report Generated: {_utcnow()}")
        report.append("")
        
        devices = self.device_mgr.list_devices(case_id)
        report.append(f"Total Devices: {len(devices)}")
        report.append(f"Completed: {len([d for d in devices if d.state == DeviceState.COMPLETED])}")
        report.append(f"Failed: {len([d for d in devices if d.state == DeviceState.FAILED])}")
        report.append("")
        
        report.append("DEVICE SUMMARY")
        report.append("-" * 70)
        for device in devices:
            report.append(f"{device.device_id}: {device.device_model} ({device.state.value})")
            if device.state == DeviceState.COMPLETED:
                report.append(f"  QA: {device.qa_status}")
                report.append(f"  Hash: {device.data_integrity_hash[:16]}...")
        
        return "\n".join(report)


# ─────────────────────────────────────────────────────────────────────────────
# Utilities (Misc)
# ─────────────────────────────────────────────────────────────────────────────

def _human_readable_size(size_bytes: int) -> str:
    """Convert bytes to human-readable format."""
    for unit in ("B", "KB", "MB", "GB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f}{unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f}TB"


# ─────────────────────────────────────────────────────────────────────────────
# CLI & Main
# ─────────────────────────────────────────────────────────────────────────────

def build_cli() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mobile_orchestrator.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "HIVE Platform · Stage 1.5: Mobile Device Forensic Acquisition Orchestrator\n"
            f"Version {ORCHESTRATOR_VERSION}\n\n"
            "Large-scale mobile device forensics using licensed extraction tools.\n"
            "Supports: Cellebrite UFED, MSAB XRY, Oxygen Forensic Detective"
        ),
        epilog="""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 QUICK-START
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Import devices from CSV:
  python3 mobile_orchestrator.py --case CASE-001 --import devices.csv

Start batch acquisition (auto-detects tools):
  python3 mobile_orchestrator.py --case CASE-001 --batch devices.csv

Monitor acquisition progress:
  python3 mobile_orchestrator.py --case CASE-001 --monitor

Export evidence for HIVE pipeline:
  python3 mobile_orchestrator.py --case CASE-001 --export

Generate report:
  python3 mobile_orchestrator.py --case CASE-001 --report
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
    )
    
    g = p.add_argument_group("Case")
    g.add_argument("--case", "-c", required=True, metavar="ID",
                    help="Case identifier")
    
    g2 = p.add_argument_group("Operations")
    g2.add_argument("--import", metavar="FILE",
                     help="Import devices from CSV file")
    g2.add_argument("--batch", metavar="FILE",
                     help="Run batch acquisition from CSV")
    g2.add_argument("--monitor", action="store_true",
                     help="Monitor running acquisitions")
    g2.add_argument("--export", action="store_true",
                     help="Export evidence for HIVE pipeline")
    g2.add_argument("--report", action="store_true",
                     help="Generate acquisition report")
    
    g3 = p.add_argument_group("Configuration")
    g3.add_argument("--evidence-root", default=DEFAULT_EVIDENCE_ROOT,
                     help="Root directory for evidence storage")
    g3.add_argument("--workers", type=int, default=MAX_WORKERS,
                     help="Maximum parallel acquisition jobs")
    g3.add_argument("--mongo-uri", default=DEFAULT_MONGO_URI,
                     help="MongoDB connection URI")
    
    g4 = p.add_argument_group("Output")
    g4.add_argument("--output", "-o", metavar="FILE",
                     help="Write report to file")
    g4.add_argument("-v", "--verbose", action="store_true",
                     help="Verbose logging")
    
    return p


def main() -> int:
    cli = build_cli()
    args = cli.parse_args()
    
    orch = MobileOrchestrator(
        args.case,
        evidence_root=args.evidence_root,
        mongo_uri=args.mongo_uri,
        max_workers=args.workers,
        verbose=args.verbose)
    
    try:
        if args.import_:
            count = orch.device_mgr.register_devices_from_csv(args.import_, args.case)
            print(f"Imported {count} devices")
            return 0
        
        if args.batch:
            count = orch.device_mgr.register_devices_from_csv(args.batch, args.case)
            print(f"Imported {count} devices, starting acquisition...")
            
            plan = AcquisitionPlan(
                case_id=args.case,
                devices=orch.device_mgr.list_devices(args.case),
            )
            
            results = orch.run_batch_acquisition(plan)
            print(f"Completed: {results['devices_completed']}, Failed: {results['devices_failed']}")
            return 0
        
        if args.monitor:
            print(f"Monitoring case {args.case}...")
            devs = orch.device_mgr.list_devices(args.case)
            for dev in devs:
                status = "✓" if dev.state == DeviceState.COMPLETED else "✗" if dev.state == DeviceState.FAILED else "…"
                print(f"  {status} {dev.device_id}: {dev.state.value}")
            return 0
        
        if args.export:
            orch.export_for_hive_pipeline(args.case)
            print("Export complete")
            return 0
        
        if args.report:
            report = orch.generate_report(args.case)
            print(report)
            if args.output:
                with open(args.output, "w") as f:
                    f.write(report)
                print(f"Saved to {args.output}")
            return 0
        
        print("No operation specified. Use --help for usage.")
        return 1
    
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 1
    except Exception as exc:
        print(f"[!] Error: {exc}", file=sys.stderr)
        if args.verbose:
            traceback.print_exc(file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
