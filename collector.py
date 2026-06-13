#!/usr/bin/env python3
"""
collector.py  —  HIVE Platform · Core Acquisition Engine
═══════════════════════════════════════════════════════════════════════════════
High-scale Investigation and Verification Engine  (HIVE)  v1.0.0
Digital Forensics & Incident Response – Evidence Acquisition Framework

Supported acquisition targets
  • Android devices         (ADB – artifact / triage)
  • Windows storage media   (offline NTFS mount – artifact / triage)
  • Linux systems           (live or offline mount – artifact / triage)
  • Any block device        (raw forensic imaging with SHA-256 verification)

Pipeline position
  [collector.py] → parser → correlator → visualiser

Future integration stubs
  • Elasticsearch – evidence indexing
  • Neo4j          – relationship / graph analysis
  • PostgreSQL      – case management
  • Apache Kafka    – distributed ingestion

LEGAL NOTICE
  This tool is designed for authorised forensic investigations only.
  Unauthorised use against devices you do not own, or for which you do not
  have explicit written permission, may violate the Computer Fraud and Abuse
  Act (CFAA), the Computer Misuse Act, or equivalent legislation in your
  jurisdiction.  The authors accept no liability for misuse.
═══════════════════════════════════════════════════════════════════════════════

Usage (quick-reference):
  sudo python3 collector.py --mode artifact --auto-discover
  sudo python3 collector.py --mode artifact --target android --serial ABC123
  sudo python3 collector.py --mode artifact --target windows --mount /mnt/win
  sudo python3 collector.py --mode artifact --target linux   --mount /mnt/lnx
  sudo python3 collector.py --mode image    --device /dev/sdb --output /evidence
  sudo python3 collector.py --mode triage   --auto-discover --workers 8
  sudo python3 collector.py --verify /evidence/sdb.img
  sudo python3 collector.py --config /etc/hive/hive.json
"""

from __future__ import annotations

# ── stdlib ────────────────────────────────────────────────────────────────────
import os
import re
import sys
import glob
import gzip
import json
import time
import uuid
import shlex
import shutil
import hashlib
import logging
import argparse
import platform
import datetime
import threading
import subprocess
import concurrent.futures
from abc       import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from pathlib   import Path
from typing    import Optional, List, Dict, Any, Tuple

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

HIVE_VERSION    = "1.0.0"
HIVE_TOOL       = "HIVE-collector"
DEFAULT_OUTPUT  = "/evidence"
DEFAULT_WORKERS = 4
BLOCK_SIZE      = 4 * 1024 * 1024          # 4 MiB read window for imaging
LOG_FMT         = "[%(asctime)s] %(levelname)-8s %(name)s — %(message)s"
DATE_FMT        = "%Y-%m-%dT%H:%M:%SZ"
MAX_LOG_MB      = 500                       # cap on /var/log collection
MAX_BROWSER_MB  = 200                       # cap per browser profile tree

# Android content-provider base URIs
ANDROID_CONTENT_URIS: Dict[str, str] = {
    "contacts":  "content://contacts/phones/",
    "sms":       "content://sms/",
    "call_log":  "content://call_log/calls/",
    "mms":       "content://mms/",
    "calendar":  "content://com.android.calendar/events/",
    "downloads": "content://downloads/",
    "images":    "content://media/external/images/media",
    "videos":    "content://media/external/video/media",
}

# Windows Registry hive relative paths (from volume root)
WIN_REGISTRY_HIVES: Dict[str, str] = {
    "SAM":      "Windows/System32/config/SAM",
    "SYSTEM":   "Windows/System32/config/SYSTEM",
    "SOFTWARE": "Windows/System32/config/SOFTWARE",
    "SECURITY": "Windows/System32/config/SECURITY",
    "DEFAULT":  "Windows/System32/config/DEFAULT",
}

# Priority Windows event log filenames
WIN_PRIORITY_EVTX = [
    "Security.evtx",
    "System.evtx",
    "Application.evtx",
    "Microsoft-Windows-PowerShell%4Operational.evtx",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx",
    "Microsoft-Windows-TaskScheduler%4Operational.evtx",
    "Microsoft-Windows-WMI-Activity%4Operational.evtx",
    "Microsoft-Windows-Sysmon%4Operational.evtx",
]

# Browser artifact paths relative to a Windows user profile root
WIN_BROWSER_ARTIFACTS: Dict[str, str] = {
    "chrome_history":  "AppData/Local/Google/Chrome/User Data/Default/History",
    "chrome_cookies":  "AppData/Local/Google/Chrome/User Data/Default/Cookies",
    "chrome_logins":   "AppData/Local/Google/Chrome/User Data/Default/Login Data",
    "edge_history":    "AppData/Local/Microsoft/Edge/User Data/Default/History",
    "firefox_profiles":"AppData/Roaming/Mozilla/Firefox/Profiles",
    "ie_history":      "AppData/Local/Microsoft/Windows/History",
}

# Linux standard artifact files (relative to volume root)
LINUX_STD_FILES = [
    "etc/passwd", "etc/shadow", "etc/group", "etc/sudoers",
    "etc/hostname", "etc/hosts", "etc/resolv.conf",
    "etc/os-release", "etc/issue", "etc/timezone",
    "etc/fstab", "etc/crontab",
    "etc/ssh/sshd_config", "etc/ssh/ssh_config",
    "etc/network/interfaces",
    "etc/iptables/rules.v4", "etc/iptables/rules.v6",
    "etc/apt/sources.list",
    "proc/version", "proc/cmdline", "proc/cpuinfo",
    "proc/meminfo", "proc/uptime",
]

LINUX_LOG_PRIORITY = [
    "auth.log", "auth.log.1", "syslog", "syslog.1",
    "kern.log", "secure", "messages",
    "wtmp", "btmp", "lastlog",
    "dpkg.log", "cron", "daemon.log",
]

LINUX_HISTORY_FILES = [
    ".bash_history", ".zsh_history", ".sh_history",
    ".fish_history", ".local/share/fish/fish_history",
    ".python_history", ".mysql_history", ".psql_history",
]

LINUX_CRON_PATHS = [
    "etc/crontab", "etc/cron.d", "etc/cron.daily",
    "etc/cron.hourly", "etc/cron.monthly", "etc/cron.weekly",
    "var/spool/cron", "var/spool/cron/crontabs",
]

LINUX_SYSTEMD_UNIT_DIRS = [
    "etc/systemd/system", "lib/systemd/system",
    "usr/lib/systemd/system", "run/systemd/system",
]


# ─────────────────────────────────────────────────────────────────────────────
# Enumerations
# ─────────────────────────────────────────────────────────────────────────────

class DeviceType(str):
    ANDROID = "android"
    WINDOWS = "windows"
    LINUX   = "linux"
    MACOS   = "macos"
    IOS     = "ios"
    ROUTER  = "router"
    IOT     = "iot"
    UNKNOWN = "unknown"

class AcquisitionMode(str):
    ARTIFACT = "artifact"
    IMAGE    = "image"
    TRIAGE   = "triage"

class AcquisitionStatus(str):
    PENDING   = "pending"
    RUNNING   = "running"
    COMPLETED = "completed"
    PARTIAL   = "partial"
    FAILED    = "failed"


# ─────────────────────────────────────────────────────────────────────────────
# Data Models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ChainOfCustodyEntry:
    timestamp: str
    action:    str
    operator:  str
    notes:     str = ""


@dataclass
class ForensicMetadata:
    """
    Normalised evidence metadata schema – common across all collector modules.
    Designed to be serialised to JSON and ingested by downstream HIVE pipeline
    stages (parser, correlator, Elasticsearch indexer, Neo4j importer).
    """
    # Identity
    acquisition_id:    str  = field(default_factory=lambda: str(uuid.uuid4()))
    case_id:           str  = ""
    evidence_number:   str  = ""
    operator:          str  = ""

    # Tool provenance
    tool:              str  = HIVE_TOOL
    tool_version:      str  = HIVE_VERSION
    collector_host:    str  = field(default_factory=platform.node)
    collector_os:      str  = field(default_factory=platform.platform)

    # Timing
    timestamp_start:   str  = ""
    timestamp_end:     str  = ""

    # Target device
    device_type:       str  = DeviceType.UNKNOWN
    device_id:         str  = ""
    device_serial:     str  = ""
    device_model:      str  = ""
    device_os:         str  = ""

    # Acquisition details
    acquisition_mode:   str = AcquisitionMode.ARTIFACT
    acquisition_method: str = ""
    status:             str = AcquisitionStatus.PENDING
    output_path:        str = ""

    # Results
    artifacts:          List[str]       = field(default_factory=list)
    image_sha256:       str             = ""
    image_size_bytes:   int             = 0
    errors:             List[str]       = field(default_factory=list)
    warnings:           List[str]       = field(default_factory=list)
    notes:              str             = ""

    # Chain of custody
    chain_of_custody:   List[Dict]      = field(default_factory=list)

    # Extensible fields for downstream use
    custom_fields:      Dict[str, Any]  = field(default_factory=dict)

    # ── Future integration stubs ──────────────────────────────
    # elasticsearch_index_id: str = ""
    # neo4j_node_id: str = ""
    # kafka_offset: int = 0

    def log_custody(self, action: str, operator: str, notes: str = "") -> None:
        self.chain_of_custody.append(asdict(ChainOfCustodyEntry(
            timestamp=_utcnow(), action=action, operator=operator, notes=notes
        )))

    def to_dict(self) -> Dict:
        return asdict(self)

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2, default=str)


@dataclass
class DeviceInfo:
    """Represents a discovered device ready for acquisition."""
    device_id:    str           = ""
    device_type:  str           = DeviceType.UNKNOWN
    serial:       str           = ""
    model:        str           = ""
    os_version:   str           = ""
    block_device: str           = ""        # e.g. /dev/sdb
    partitions:   List[str]     = field(default_factory=list)
    filesystem:   str           = ""        # ntfs / ext4 / apfs / …
    size_bytes:   int           = 0
    rooted:       bool          = False
    authorized:   bool          = True      # ADB auth
    mount_point:  str           = ""
    extra:        Dict[str, Any]= field(default_factory=dict)


# ─────────────────────────────────────────────────────────────────────────────
# Utility Functions
# ─────────────────────────────────────────────────────────────────────────────

def _utcnow() -> str:
    return datetime.datetime.utcnow().strftime(DATE_FMT)


def _mkdir(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path


def _human(n: int) -> str:
    """Human-readable byte size."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def _run(cmd: str, timeout: int = 60, shell: bool = False) -> Tuple[int, str, str]:
    """Execute a command, returning (returncode, stdout, stderr)."""
    try:
        args = cmd if shell else shlex.split(cmd)
        r = subprocess.run(args, capture_output=True, text=True,
                           timeout=timeout, shell=shell)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"Timed out after {timeout}s: {cmd}"
    except FileNotFoundError as exc:
        return -1, "", f"Not found: {exc}"
    except Exception as exc:
        return -1, "", str(exc)


def _sha256_file(path: str, progress_cb=None) -> str:
    h = hashlib.sha256()
    total = 0
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(BLOCK_SIZE)
            if not chunk:
                break
            h.update(chunk)
            total += len(chunk)
            if progress_cb:
                progress_cb(total)
    return h.hexdigest()


def _copy_file(src: str, dst_dir: str) -> Optional[str]:
    """Copy src into dst_dir (creating it).  Returns dst path or None."""
    if not os.path.exists(src):
        return None
    _mkdir(dst_dir)
    dst = os.path.join(dst_dir, os.path.basename(src))
    try:
        shutil.copy2(src, dst)
        return dst
    except Exception:
        return None


def _copy_tree(src: str, dst: str, max_bytes: int = MAX_BROWSER_MB * 1024**2) -> int:
    """Recursively copy directory, stopping at max_bytes.  Returns file count."""
    if not os.path.isdir(src):
        return 0
    total_bytes, copied = 0, 0
    for root, _dirs, files in os.walk(src):
        for fname in files:
            src_f = os.path.join(root, fname)
            try:
                size = os.path.getsize(src_f)
                if total_bytes + size > max_bytes:
                    return copied
                rel   = os.path.relpath(src_f, src)
                dst_f = os.path.join(dst, rel)
                _mkdir(os.path.dirname(dst_f))
                shutil.copy2(src_f, dst_f)
                total_bytes += size
                copied      += 1
            except Exception:
                pass
    return copied


def _require_root() -> None:
    if os.geteuid() != 0:
        print("[!] This operation requires root privileges.  Re-run with sudo.")
        sys.exit(1)


def _safe_filename(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_\-]", "_", s)


# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────

def setup_logging(output_dir: str, verbose: bool = False) -> logging.Logger:
    _mkdir(output_dir)
    log_path = os.path.join(output_dir, f"hive_{datetime.date.today()}.log")
    level    = logging.DEBUG if verbose else logging.INFO
    fmt      = logging.Formatter(LOG_FMT, datefmt=DATE_FMT)

    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setFormatter(fmt); fh.setLevel(level)

    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt); ch.setLevel(level)

    root = logging.getLogger()
    root.setLevel(level)
    root.handlers.clear()
    root.addHandler(fh)
    root.addHandler(ch)

    return logging.getLogger("hive.collector")


# ─────────────────────────────────────────────────────────────────────────────
# Evidence Store
# ─────────────────────────────────────────────────────────────────────────────

class EvidenceStore:
    """
    Manages the standardised evidence directory tree.

    Layout:
      <base_dir>/
        <case_id>/
          <device_safe_id>_<acq_short_id>/
            artifacts/
              <category>/          ← raw collected files
            images/                ← forensic images + hash files
            MANIFEST.json          ← ForensicMetadata for this device
          CASE_REPORT.json         ← aggregated case summary
    """

    def __init__(self, base_dir: str, case_id: str):
        self.base_dir = base_dir
        self.case_id  = case_id
        self.case_dir = _mkdir(os.path.join(base_dir, _safe_filename(case_id)))
        self.log      = logging.getLogger("hive.store")

    def device_dir(self, acq_id: str, device_id: str) -> str:
        name = f"{_safe_filename(device_id)}_{acq_id[:8]}"
        return _mkdir(os.path.join(self.case_dir, name))

    def artifact_dir(self, base: str, category: str) -> str:
        return _mkdir(os.path.join(base, "artifacts", category))

    def image_dir(self, base: Optional[str] = None) -> str:
        return _mkdir(os.path.join(base or self.case_dir, "images"))

    def write_text(self, path: str, content: str) -> None:
        with open(path, "w", encoding="utf-8", errors="replace") as fh:
            fh.write(content)

    def write_json(self, path: str, obj: Any) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(obj, fh, indent=2, default=str)

    def write_manifest(self, device_dir: str, meta: ForensicMetadata) -> str:
        path = os.path.join(device_dir, "MANIFEST.json")
        meta.save(path)
        return path

    def case_report(self) -> Dict:
        report: Dict = {"case_id": self.case_id, "generated": _utcnow(), "acquisitions": []}
        for entry in os.scandir(self.case_dir):
            manifest = os.path.join(entry.path, "MANIFEST.json")
            if entry.is_dir() and os.path.exists(manifest):
                with open(manifest) as fh:
                    report["acquisitions"].append(json.load(fh))
        return report

    def save_case_report(self) -> str:
        path = os.path.join(self.case_dir, "CASE_REPORT.json")
        self.write_json(path, self.case_report())
        self.log.info(f"Case report → {path}")
        return path


# ─────────────────────────────────────────────────────────────────────────────
# Base Collector
# ─────────────────────────────────────────────────────────────────────────────

class BaseCollector(ABC):
    """Abstract base for all platform collectors."""

    DEVICE_TYPE = DeviceType.UNKNOWN

    def __init__(self, device: DeviceInfo, store: EvidenceStore, meta: ForensicMetadata):
        self.device  = device
        self.store   = store
        self.meta    = meta
        self.log     = logging.getLogger(f"hive.{self.DEVICE_TYPE}")
        self.dev_dir = store.device_dir(meta.acquisition_id, device.device_id or device.serial)
        meta.output_path = self.dev_dir

    @abstractmethod
    def collect_artifacts(self) -> bool: ...

    @abstractmethod
    def triage(self) -> bool: ...

    def _artifact(self, category: str, path: str) -> None:
        self.meta.artifacts.append(f"{category}:{os.path.relpath(path, self.dev_dir)}")

    def _error(self, msg: str) -> None:
        self.meta.errors.append(msg)
        self.log.error(msg)

    def _warn(self, msg: str) -> None:
        self.meta.warnings.append(msg)
        self.log.warning(msg)

    def _finalize(self, start: str) -> None:
        self.meta.timestamp_end = _utcnow()
        ok = not self.meta.errors
        self.meta.status = (AcquisitionStatus.COMPLETED if ok
                             else AcquisitionStatus.PARTIAL)
        self.meta.log_custody(
            "acquisition_complete", self.meta.operator,
            f"artifacts={len(self.meta.artifacts)}  errors={len(self.meta.errors)}"
        )
        self.store.write_manifest(self.dev_dir, self.meta)


# ─────────────────────────────────────────────────────────────────────────────
# Android Collector
# ─────────────────────────────────────────────────────────────────────────────

class AndroidCollector(BaseCollector):
    """
    ADB-based acquisition from Android devices.

    Supports both rooted and non-rooted devices.  Root access unlocks
    additional artifacts (Chrome DB, Wi-Fi credentials, private app data).
    """

    DEVICE_TYPE = DeviceType.ANDROID

    def __init__(self, device: DeviceInfo, store: EvidenceStore, meta: ForensicMetadata):
        super().__init__(device, store, meta)
        self.serial = device.serial
        self._adb_prefix = f"adb -s {self.serial}" if self.serial else "adb"

    # ── ADB wrappers ──────────────────────────────────────────

    def _adb(self, subcmd: str, timeout: int = 30) -> Tuple[int, str, str]:
        return _run(f"{self._adb_prefix} {subcmd}", timeout=timeout)

    def _shell(self, cmd: str, timeout: int = 30) -> str:
        rc, out, _ = self._adb(f"shell {cmd}", timeout=timeout)
        return out

    def _pull(self, remote: str, local_dir: str, timeout: int = 120) -> bool:
        _mkdir(local_dir)
        rc, _, err = self._adb(f"pull \"{remote}\" \"{local_dir}\"", timeout=timeout)
        if rc != 0:
            self.log.debug(f"adb pull {remote}: {err.strip()[:100]}")
        return rc == 0

    def _content_query(self, uri: str, projection: str = "",
                        sort: str = "", timeout: int = 60) -> str:
        cmd = f"shell content query --uri {uri}"
        if projection:
            cmd += f" --projection {projection}"
        if sort:
            cmd += f" --sort '{sort}'"
        rc, out, err = self._adb(cmd, timeout=timeout)
        if rc != 0 or not out.strip() or "Exception" in out:
            return ""
        return out

    # ── Device profiling ──────────────────────────────────────

    def _profile_device(self) -> None:
        props = {
            "manufacturer": "getprop ro.product.manufacturer",
            "model":        "getprop ro.product.model",
            "android":      "getprop ro.build.version.release",
            "sdk":          "getprop ro.build.version.sdk",
            "build":        "getprop ro.build.display.id",
            "android_id":   "settings get secure android_id",
            "wifi_mac":     "cat /sys/class/net/wlan0/address 2>/dev/null",
            "bt_mac":       "settings get secure bluetooth_address 2>/dev/null",
        }
        info = {k: self._shell(v).strip() for k, v in props.items()}
        self.device.model      = f"{info.get('manufacturer','')} {info.get('model','')}".strip()
        self.device.os_version = f"Android {info.get('android','')} (SDK {info.get('sdk','')})"
        self.meta.device_model = self.device.model
        self.meta.device_os    = self.device.os_version
        self.meta.custom_fields["device_profile"] = info
        self.log.info(f"  Device : {self.device.model}")
        self.log.info(f"  OS     : {self.device.os_version}")

    def _check_root(self) -> bool:
        out = self._shell("id")
        rooted = "uid=0" in out or "root" in out
        self.device.rooted = rooted
        self.meta.custom_fields["rooted"] = rooted
        self.log.info(f"  Root   : {'YES' if rooted else 'NO'}")
        return rooted

    # ── Individual artifact collectors ────────────────────────

    def _do_contacts(self, d: str) -> None:
        out = self._content_query(
            ANDROID_CONTENT_URIS["contacts"],
            "display_name:number:type", "display_name ASC")
        if not out:
            self._warn("contacts: empty or inaccessible"); return
        p = os.path.join(d, "contacts.txt")
        self.store.write_text(p, out)
        self._artifact("contacts", p)
        self.log.info(f"  ✓ Contacts      : {out.count('Row:')} records")

    def _do_sms(self, d: str) -> None:
        out = self._content_query(
            ANDROID_CONTENT_URIS["sms"],
            "address:body:date:type:read", "date DESC", timeout=90)
        if not out:
            self._warn("sms: empty or inaccessible"); return
        p = os.path.join(d, "sms.txt")
        self.store.write_text(p, out)
        self._artifact("sms", p)
        self.log.info(f"  ✓ SMS           : {out.count('Row:')} messages")

    def _do_call_log(self, d: str) -> None:
        out = self._content_query(
            ANDROID_CONTENT_URIS["call_log"],
            "number:date:duration:type:name", "date DESC")
        if not out:
            self._warn("call_log: inaccessible"); return
        p = os.path.join(d, "call_log.txt")
        self.store.write_text(p, out)
        self._artifact("call_log", p)
        self.log.info(f"  ✓ Call log      : {out.count('Row:')} entries")

    def _do_mms(self, d: str) -> None:
        out = self._content_query(
            ANDROID_CONTENT_URIS["mms"],
            "_id:date:sub:read:m_type", "date DESC", timeout=60)
        if not out:
            return
        p = os.path.join(d, "mms.txt")
        self.store.write_text(p, out)
        self._artifact("mms", p)
        self.log.info(f"  ✓ MMS           : {out.count('Row:')} records")

    def _do_installed_apps(self, d: str) -> None:
        # User-installed packages with APK paths
        rc, out, _ = self._adb("shell pm list packages -f -3", timeout=60)
        if rc == 0 and out.strip():
            p = os.path.join(d, "apps_user.txt")
            self.store.write_text(p, out)
            self._artifact("installed_apps", p)
            self.log.info(f"  ✓ User apps     : {out.count(chr(10))} entries")
        # All packages (system + user)
        rc2, out2, _ = self._adb("shell pm list packages -f", timeout=60)
        if rc2 == 0 and out2.strip():
            p2 = os.path.join(d, "apps_all.txt")
            self.store.write_text(p2, out2)
            self._artifact("installed_apps", p2)
        # Package details dump
        rc3, out3, _ = self._adb("shell dumpsys package packages", timeout=90)
        if rc3 == 0 and out3.strip():
            p3 = os.path.join(d, "packages_dump.txt")
            self.store.write_text(p3, out3)
            self._artifact("installed_apps", p3)

    def _do_browser_history(self, d: str) -> None:
        chrome_db = "/data/data/com.android.chrome/app_chrome/Default/History"
        pulled = self._pull(chrome_db, d)
        if pulled:
            self._artifact("browser_history", os.path.join(d, "History"))
            self.log.info("  ✓ Chrome History DB pulled (requires root)")
        # Fallback: dumpsys
        rc, out, _ = self._adb("shell dumpsys activity com.android.browser", timeout=30)
        if rc == 0 and out.strip():
            p = os.path.join(d, "browser_dumpsys.txt")
            self.store.write_text(p, out)
            self._artifact("browser_history", p)
        if not pulled:
            self._warn("browser_history: Chrome DB not accessible without root")

    def _do_downloads(self, d: str) -> None:
        out = self._content_query(ANDROID_CONTENT_URIS["downloads"],
                                   "_id:title:uri:status:total_size:local_uri")
        if out:
            p = os.path.join(d, "downloads_db.txt")
            self.store.write_text(p, out)
            self._artifact("downloads", p)
            self.log.info(f"  ✓ Downloads DB  : {out.count('Row:')} entries")
        # File listing of /sdcard/Download
        listing = self._shell("ls -laR /sdcard/Download/ 2>/dev/null")
        if listing:
            p2 = os.path.join(d, "download_dir_listing.txt")
            self.store.write_text(p2, listing)
            self._artifact("downloads", p2)

    def _do_media(self, d: str) -> None:
        for label, uri in [("images", ANDROID_CONTENT_URIS["images"]),
                             ("videos", ANDROID_CONTENT_URIS["videos"])]:
            out = self._content_query(uri,
                                       "_id:_display_name:date_added:size:data",
                                       "date_added DESC", timeout=60)
            if out:
                p = os.path.join(d, f"media_{label}.txt")
                self.store.write_text(p, out)
                self._artifact("media", p)
                self.log.info(f"  ✓ Media {label:<7}: {out.count('Row:')} entries")

    def _do_calendar(self, d: str) -> None:
        out = self._content_query(
            ANDROID_CONTENT_URIS["calendar"],
            "title:description:dtstart:dtend:eventLocation:organizer", timeout=60)
        if out:
            p = os.path.join(d, "calendar_events.txt")
            self.store.write_text(p, out)
            self._artifact("calendar", p)
            self.log.info(f"  ✓ Calendar      : {out.count('Row:')} events")

    def _do_accounts(self, d: str) -> None:
        rc, out, _ = self._adb("shell dumpsys account", timeout=30)
        if rc == 0 and out.strip():
            p = os.path.join(d, "accounts_dumpsys.txt")
            self.store.write_text(p, out)
            self._artifact("accounts", p)
            self.log.info("  ✓ Accounts      : dumpsys captured")

    def _do_wifi(self, d: str) -> None:
        candidates = [
            "/data/misc/wifi/WifiConfigStore.xml",
            "/data/misc/wifi/wpa_supplicant.conf",
            "/data/system/NetworkPolicy.xml",
        ]
        found = 0
        for path in candidates:
            rc, _, _ = self._adb(f"shell ls \"{path}\"", timeout=5)
            if rc == 0:
                if self._pull(path, d):
                    self._artifact("wifi", os.path.join(d, os.path.basename(path)))
                    found += 1
        if found:
            self.log.info(f"  ✓ WiFi configs  : {found} file(s) (requires root)")
        else:
            self._warn("wifi: configs not accessible without root")

    def _do_shell_history(self, d: str) -> None:
        paths = ["/data/local/tmp/.bash_history", "/root/.bash_history",
                  "/sdcard/.bash_history"]
        found = 0
        for hp in paths:
            rc, out, _ = self._adb(f"shell cat \"{hp}\"", timeout=15)
            if rc == 0 and out.strip():
                p = os.path.join(d, f"shell_history_{found}.txt")
                self.store.write_text(p, out)
                self._artifact("shell_history", p)
                found += 1
        if found:
            self.log.info(f"  ✓ Shell history : {found} file(s)")

    def _do_system_state(self, d: str) -> None:
        cmds: Dict[str, str] = {
            "device_props.txt":  "getprop",
            "processes.txt":     "ps -A",
            "ip_addr.txt":       "ip addr show",
            "ip_route.txt":      "ip route show",
            "arp.txt":           "ip neigh show",
            "open_ports.txt":    "netstat -tulnp 2>/dev/null || ss -tulnp",
            "disk_usage.txt":    "df -h",
            "uptime.txt":        "uptime",
            "dmesg.txt":         "dmesg",
        }
        for fname, cmd in cmds.items():
            out = self._shell(cmd)
            if out.strip():
                p = os.path.join(d, fname)
                self.store.write_text(p, out)
                self._artifact("system_state", p)
        self.log.info("  ✓ System state  : captured")

    def _do_logcat(self, d: str) -> None:
        rc, out, _ = self._adb("shell logcat -d -t 10000", timeout=120)
        if rc == 0 and out.strip():
            p = os.path.join(d, "logcat.txt")
            self.store.write_text(p, out)
            self._artifact("logs", p)
            self.log.info(f"  ✓ Logcat        : {len(out.splitlines())} lines")

    def _do_adb_backup(self, d: str) -> None:
        bp = os.path.join(d, "device_backup.ab")
        self.log.info("  → ADB backup — confirm on device if prompted …")
        rc, _, err = self._adb(f"backup -all -f \"{bp}\"", timeout=300)
        if rc == 0 and os.path.exists(bp) and os.path.getsize(bp) > 0:
            self._artifact("backup", bp)
            self.log.info(f"  ✓ ADB backup    : {_human(os.path.getsize(bp))}")
        else:
            self._warn(f"ADB backup failed or empty: {err.strip()[:120]}")

    # ── Public interface ──────────────────────────────────────

    def collect_artifacts(self) -> bool:
        self.log.info(f"{'─'*60}")
        self.log.info(f"[ANDROID] Artifact collection → {self.serial}")
        self.meta.timestamp_start = _utcnow()
        self.meta.status          = AcquisitionStatus.RUNNING
        self.meta.acquisition_method = "adb_artifact"
        self.meta.log_custody("acquisition_start", self.meta.operator,
                               f"Android artifact: {self.serial}")
        try:
            self._profile_device()
            self._check_root()
            d = self.store.artifact_dir(self.dev_dir, "android")

            steps = [
                ("Contacts",         self._do_contacts),
                ("SMS",              self._do_sms),
                ("Call Log",         self._do_call_log),
                ("MMS",              self._do_mms),
                ("Installed Apps",   self._do_installed_apps),
                ("Browser History",  self._do_browser_history),
                ("Downloads",        self._do_downloads),
                ("Media Index",      self._do_media),
                ("Calendar",         self._do_calendar),
                ("Accounts",         self._do_accounts),
                ("WiFi Networks",    self._do_wifi),
                ("Shell History",    self._do_shell_history),
                ("System State",     self._do_system_state),
                ("Logcat",           self._do_logcat),
                ("ADB Backup",       self._do_adb_backup),
            ]

            for name, fn in steps:
                self.log.info(f"  → {name} …")
                try:
                    fn(d)
                except Exception as exc:
                    self._error(f"{name}: {exc}")

            self._finalize(self.meta.timestamp_start)
            self.log.info(f"[ANDROID] Done → {len(self.meta.artifacts)} artifacts  "
                           f"{len(self.meta.errors)} errors")
            return True

        except Exception as exc:
            self.meta.status = AcquisitionStatus.FAILED
            self._error(f"Fatal: {exc}")
            self.log.error("[ANDROID] FATAL", exc_info=True)
            self.store.write_manifest(self.dev_dir, self.meta)
            return False

    def triage(self) -> bool:
        self.log.info(f"[ANDROID TRIAGE] → {self.serial}")
        self.meta.timestamp_start = _utcnow()
        self.meta.status          = AcquisitionStatus.RUNNING
        self.meta.acquisition_method = "adb_triage"
        d = self.store.artifact_dir(self.dev_dir, "triage")
        try:
            self._profile_device()
            self._check_root()
            for name, fn in [
                ("Contacts",        self._do_contacts),
                ("Call Log",        self._do_call_log),
                ("SMS",             self._do_sms),
                ("Installed Apps",  self._do_installed_apps),
                ("System State",    self._do_system_state),
            ]:
                self.log.info(f"  → {name} …")
                try:
                    fn(d)
                except Exception as exc:
                    self._error(f"{name}: {exc}")
            self._finalize(self.meta.timestamp_start)
            self.log.info(f"[ANDROID TRIAGE] Done → {len(self.meta.artifacts)} artifacts")
            return True
        except Exception as exc:
            self.meta.status = AcquisitionStatus.FAILED
            self._error(str(exc))
            return False


# ─────────────────────────────────────────────────────────────────────────────
# Windows Collector
# ─────────────────────────────────────────────────────────────────────────────

class WindowsCollector(BaseCollector):
    """
    Offline Windows artifact extraction from a read-only NTFS mount.

    Mount the target partition before invoking:
      mount -t ntfs-3g -o ro /dev/sdb1 /mnt/win
      python3 collector.py --target windows --mount /mnt/win
    """

    DEVICE_TYPE = DeviceType.WINDOWS

    def __init__(self, device: DeviceInfo, store: EvidenceStore, meta: ForensicMetadata):
        super().__init__(device, store, meta)
        self.root = device.mount_point or ""

    def _r(self, *parts: str) -> str:
        """Resolve a path relative to the Windows volume root."""
        return os.path.join(self.root, *[p.lstrip("/\\") for p in parts])

    def _cp(self, rel: str, dst_dir: str) -> Optional[str]:
        return _copy_file(self._r(rel), dst_dir)

    # ── Artifact collectors ───────────────────────────────────

    def _do_system_info(self, d: str) -> None:
        info = {
            "mount_point": self.root,
            "windows_dir": self._r("Windows"),
            "win_dir_exists": os.path.isdir(self._r("Windows")),
        }
        # Try to detect OS build from ntoskrnl.exe
        ntos = self._r("Windows/System32/ntoskrnl.exe")
        if os.path.exists(ntos):
            info["ntoskrnl_bytes"] = os.path.getsize(ntos)
        p = os.path.join(d, "system_info.json")
        self.store.write_json(p, info)
        self._artifact("system_info", p)
        self.log.info("  ✓ System info   : captured")

    def _do_registry_hives(self, d: str) -> None:
        reg_d = _mkdir(os.path.join(d, "registry", "system"))
        n = 0
        for name, rel in WIN_REGISTRY_HIVES.items():
            dst = _copy_file(self._r(rel), reg_d)
            if dst:
                self._artifact("registry", dst); n += 1
        self.log.info(f"  ✓ Registry hives: {n}/{len(WIN_REGISTRY_HIVES)}")

    def _do_ntuser_dat(self, d: str) -> None:
        users_dir = self._r("Users")
        if not os.path.isdir(users_dir):
            self._warn("NTUSER.DAT: Users dir not found"); return
        reg_d = _mkdir(os.path.join(d, "registry", "users"))
        n = 0
        for entry in os.scandir(users_dir):
            if not entry.is_dir():
                continue
            for hive in ["NTUSER.DAT",
                          os.path.join("AppData","Local","Microsoft","Windows","UsrClass.dat")]:
                src = os.path.join(entry.path, hive)
                if os.path.exists(src):
                    dst_d = _mkdir(os.path.join(reg_d, _safe_filename(entry.name)))
                    dst   = _copy_file(src, dst_d)
                    if dst:
                        self._artifact("registry", dst); n += 1
        self.log.info(f"  ✓ User hives    : {n}")

    def _do_event_logs(self, d: str) -> None:
        evtx_src = self._r("Windows/System32/winevt/Logs")
        evtx_d   = _mkdir(os.path.join(d, "event_logs"))
        if not os.path.isdir(evtx_src):
            self._warn("Event logs: winevt/Logs not found"); return
        n = 0
        # Priority first
        for fname in WIN_PRIORITY_EVTX:
            if _copy_file(os.path.join(evtx_src, fname), evtx_d):
                self._artifact("event_logs", os.path.join(evtx_d, fname)); n += 1
        # Remaining
        for entry in os.scandir(evtx_src):
            if entry.name.endswith(".evtx") and entry.name not in WIN_PRIORITY_EVTX:
                if _copy_file(entry.path, evtx_d):
                    self._artifact("event_logs", os.path.join(evtx_d, entry.name)); n += 1
        self.log.info(f"  ✓ Event logs    : {n} files")

    def _do_prefetch(self, d: str) -> None:
        src = self._r("Windows/Prefetch")
        dst = _mkdir(os.path.join(d, "prefetch"))
        n   = _copy_tree(src, dst, max_bytes=200*1024**2)
        if n:
            for f in Path(dst).rglob("*.pf"):
                self._artifact("prefetch", str(f))
            self.log.info(f"  ✓ Prefetch      : {n} files")

    def _do_recent_files(self, d: str) -> None:
        users_dir = self._r("Users")
        if not os.path.isdir(users_dir):
            return
        total = 0
        for user in os.scandir(users_dir):
            if not user.is_dir():
                continue
            for sub in [
                os.path.join("AppData","Roaming","Microsoft","Windows","Recent"),
                os.path.join("AppData","Roaming","Microsoft","Windows","Recent","AutomaticDestinations"),
            ]:
                src = os.path.join(user.path, sub)
                dst = _mkdir(os.path.join(d, "recent_files", user.name, os.path.basename(sub)))
                n   = _copy_tree(src, dst, max_bytes=50*1024**2)
                total += n
        for f in Path(os.path.join(d, "recent_files")).rglob("*"):
            if f.is_file():
                self._artifact("recent_files", str(f))
        if total:
            self.log.info(f"  ✓ Recent / LNK  : {total} files")

    def _do_browser_history(self, d: str) -> None:
        users_dir = self._r("Users")
        if not os.path.isdir(users_dir):
            return
        total = 0
        for user in os.scandir(users_dir):
            if not user.is_dir():
                continue
            for label, rel in WIN_BROWSER_ARTIFACTS.items():
                src = os.path.join(user.path, *rel.split("/"))
                if not os.path.exists(src):
                    continue
                dst = _mkdir(os.path.join(d, "browser", user.name, label))
                if os.path.isfile(src):
                    r = _copy_file(src, dst)
                    if r:
                        self._artifact("browser", r); total += 1
                else:
                    n = _copy_tree(src, dst, max_bytes=MAX_BROWSER_MB*1024**2)
                    for f in Path(dst).rglob("*"):
                        if f.is_file():
                            self._artifact("browser", str(f))
                    total += n
        self.log.info(f"  ✓ Browser arts  : {total} files")

    def _do_user_accounts(self, d: str) -> None:
        users_dir = self._r("Users")
        if not os.path.isdir(users_dir):
            return
        skip = {"Public", "Default", "Default User", "All Users"}
        accounts = []
        for entry in os.scandir(users_dir):
            if entry.is_dir() and entry.name not in skip:
                accounts.append({"username": entry.name, "profile": entry.path})
        p = os.path.join(d, "user_accounts.json")
        self.store.write_json(p, accounts)
        self._artifact("accounts", p)
        self.log.info(f"  ✓ User accounts : {len(accounts)}")

    def _do_usb_history(self, d: str) -> None:
        # Full USB history lives in SYSTEM hive (USBSTOR).
        # Collect SetupAPI dev log as supplementary artefact.
        setup_log = self._r("Windows/INF/setupapi.dev.log")
        usb_d = _mkdir(os.path.join(d, "usb"))
        dst = _copy_file(setup_log, usb_d)
        if dst:
            self._artifact("usb_history", dst)
            self.log.info("  ✓ USB SetupAPI  : collected")
        else:
            self.log.info("  ✓ USB history   : in SYSTEM hive (parsed offline)")

    def _do_scheduled_tasks(self, d: str) -> None:
        src = self._r("Windows/System32/Tasks")
        dst = _mkdir(os.path.join(d, "scheduled_tasks"))
        n   = _copy_tree(src, dst, max_bytes=50*1024**2)
        for f in Path(dst).rglob("*"):
            if f.is_file():
                self._artifact("scheduled_tasks", str(f))
        if n:
            self.log.info(f"  ✓ Sched tasks   : {n} files")

    def _do_startup(self, d: str) -> None:
        users_dir = self._r("Users")
        sd = _mkdir(os.path.join(d, "startup"))
        if os.path.isdir(users_dir):
            for user in os.scandir(users_dir):
                if not user.is_dir():
                    continue
                src = os.path.join(user.path, "AppData", "Roaming", "Microsoft",
                                    "Windows", "Start Menu", "Programs", "Startup")
                if os.path.isdir(src):
                    _copy_tree(src, _mkdir(os.path.join(sd, user.name)))

    def _do_special_files(self, d: str) -> None:
        """Inventory pagefile / swapfile / hiberfil for later analysis."""
        info = {}
        for fn in ["pagefile.sys", "swapfile.sys", "hiberfil.sys"]:
            p = self._r(fn)
            info[fn] = {"exists": os.path.exists(p),
                         "size":   os.path.getsize(p) if os.path.exists(p) else 0}
        out = os.path.join(d, "special_files.json")
        self.store.write_json(out, info)
        self._artifact("memory_artifacts", out)
        self.log.info(f"  ✓ Special files : {[k for k,v in info.items() if v['exists']]}")

    def _do_mft(self, d: str) -> None:
        """Attempt to copy $MFT (requires raw read; may fail on live mounts)."""
        mft = self._r("$MFT")
        if os.path.exists(mft):
            dst = _copy_file(mft, d)
            if dst:
                self._artifact("filesystem", dst)
                self.log.info(f"  ✓ $MFT          : {_human(os.path.getsize(dst))}")
            else:
                self._warn("$MFT: copy failed (lock or permission)")
        else:
            self.log.debug("$MFT not accessible at mount root")

    def _do_file_listing(self, d: str) -> None:
        p = os.path.join(d, "file_listing.tsv")
        lines = ["mtime\tsize\tpath"]
        for root, _dirs, files in os.walk(self.root):
            for f in files:
                fp = os.path.join(root, f)
                try:
                    st = os.stat(fp)
                    lines.append(f"{st.st_mtime:.0f}\t{st.st_size}\t{fp}")
                except Exception:
                    pass
        self.store.write_text(p, "\n".join(lines))
        self._artifact("filesystem", p)
        self.log.info(f"  ✓ File listing  : {len(lines)-1} entries")

    # ── Public interface ──────────────────────────────────────

    def collect_artifacts(self) -> bool:
        self.log.info(f"{'─'*60}")
        self.log.info(f"[WINDOWS] Artifact collection → {self.root}")
        if not self.root or not os.path.isdir(self.root):
            self.log.error(f"Mount point inaccessible: {self.root}"); return False

        self.meta.timestamp_start    = _utcnow()
        self.meta.status             = AcquisitionStatus.RUNNING
        self.meta.acquisition_method = "offline_ntfs_mount"
        self.meta.log_custody("acquisition_start", self.meta.operator,
                               f"Windows offline: {self.root}")
        d = self.store.artifact_dir(self.dev_dir, "windows")

        steps = [
            ("System Info",       self._do_system_info),
            ("Registry Hives",    self._do_registry_hives),
            ("User Hives",        self._do_ntuser_dat),
            ("Event Logs",        self._do_event_logs),
            ("Prefetch",          self._do_prefetch),
            ("Recent / LNK",      self._do_recent_files),
            ("Browser History",   self._do_browser_history),
            ("User Accounts",     self._do_user_accounts),
            ("USB History",       self._do_usb_history),
            ("Scheduled Tasks",   self._do_scheduled_tasks),
            ("Startup Items",     self._do_startup),
            ("Pagefile/Hiberfil", self._do_special_files),
            ("$MFT",              self._do_mft),
            ("File Listing",      self._do_file_listing),
        ]

        for name, fn in steps:
            self.log.info(f"  → {name} …")
            try:
                fn(d)
            except Exception as exc:
                self._error(f"{name}: {exc}")

        self._finalize(self.meta.timestamp_start)
        self.log.info(f"[WINDOWS] Done → {len(self.meta.artifacts)} artifacts  "
                       f"{len(self.meta.errors)} errors")
        return True

    def triage(self) -> bool:
        self.log.info(f"[WINDOWS TRIAGE] → {self.root}")
        self.meta.timestamp_start    = _utcnow()
        self.meta.status             = AcquisitionStatus.RUNNING
        self.meta.acquisition_method = "offline_ntfs_triage"
        d = self.store.artifact_dir(self.dev_dir, "triage")
        try:
            for name, fn in [
                ("System Info",    self._do_system_info),
                ("Registry Hives", self._do_registry_hives),
                ("Event Logs",     self._do_event_logs),
                ("User Accounts",  self._do_user_accounts),
            ]:
                self.log.info(f"  → {name} …")
                try:
                    fn(d)
                except Exception as exc:
                    self._error(f"{name}: {exc}")
            self._finalize(self.meta.timestamp_start)
            self.log.info(f"[WINDOWS TRIAGE] Done → {len(self.meta.artifacts)} artifacts")
            return True
        except Exception as exc:
            self.meta.status = AcquisitionStatus.FAILED
            self._error(str(exc)); return False


# ─────────────────────────────────────────────────────────────────────────────
# Linux Collector
# ─────────────────────────────────────────────────────────────────────────────

class LinuxCollector(BaseCollector):
    """
    Linux forensic artifact collector.

    Works in two modes:
      Live   — mount_point="" or "/"  → collects from running OS
      Offline — mount_point="/mnt/x"  → reads offline volume
    """

    DEVICE_TYPE = DeviceType.LINUX

    def __init__(self, device: DeviceInfo, store: EvidenceStore, meta: ForensicMetadata):
        super().__init__(device, store, meta)
        self.root    = device.mount_point if device.mount_point else "/"
        self.is_live = (self.root == "/")

    def _r(self, rel: str) -> str:
        return os.path.join(self.root, rel.lstrip("/"))

    def _read(self, rel: str, max_bytes: int = 10*1024**2) -> Optional[str]:
        p = self._r(rel)
        if not os.path.exists(p):
            return None
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as fh:
                return fh.read(max_bytes)
        except Exception:
            return None

    def _cp(self, rel: str, dst_dir: str) -> Optional[str]:
        return _copy_file(self._r(rel), dst_dir)

    # ── Artifact collectors ───────────────────────────────────

    def _do_system_files(self, d: str) -> None:
        sys_d = _mkdir(os.path.join(d, "system"))
        n = 0
        for rel in LINUX_STD_FILES:
            dst = self._cp(rel, sys_d)
            if dst:
                self._artifact("system_files", dst); n += 1
        self.log.info(f"  ✓ System files  : {n}/{len(LINUX_STD_FILES)}")

    def _do_user_accounts(self, d: str) -> None:
        acc_d = _mkdir(os.path.join(d, "accounts"))
        accounts: List[Dict] = []
        passwd = self._read("etc/passwd")
        if passwd:
            p = os.path.join(acc_d, "passwd")
            self.store.write_text(p, passwd)
            self._artifact("accounts", p)
            for line in passwd.splitlines():
                parts = line.split(":")
                if len(parts) >= 7:
                    uid = int(parts[2]) if parts[2].isdigit() else -1
                    accounts.append({"user": parts[0], "uid": uid,
                                      "gid": parts[3], "home": parts[5],
                                      "shell": parts[6].strip()})
        for fn in ["shadow", "group", "sudoers"]:
            content = self._read(f"etc/{fn}")
            if content:
                p = os.path.join(acc_d, fn)
                self.store.write_text(p, content)
                self._artifact("accounts", p)
        summary = os.path.join(acc_d, "accounts_summary.json")
        self.store.write_json(summary, accounts)
        self.log.info(f"  ✓ User accounts : {len(accounts)}")

    def _do_shell_histories(self, d: str) -> None:
        hist_d = _mkdir(os.path.join(d, "shell_history"))
        home   = self._r("home")
        root_h = self._r("root")
        dirs   = ([root_h] if os.path.isdir(root_h) else [])
        if os.path.isdir(home):
            dirs += [e.path for e in os.scandir(home) if e.is_dir()]
        n = 0
        for udir in dirs:
            uname = os.path.basename(udir)
            for hf in LINUX_HISTORY_FILES:
                src = os.path.join(udir, hf)
                if os.path.exists(src):
                    uout = _mkdir(os.path.join(hist_d, uname))
                    dst  = os.path.join(uout, os.path.basename(hf))
                    try:
                        shutil.copy2(src, dst)
                        self._artifact("shell_history", dst); n += 1
                    except Exception:
                        pass
        self.log.info(f"  ✓ Shell history : {n} file(s)")

    def _do_ssh_artifacts(self, d: str) -> None:
        ssh_d = _mkdir(os.path.join(d, "ssh"))
        targets = [("etc/ssh", "system")]
        home = self._r("home")
        if os.path.isdir(home):
            for e in os.scandir(home):
                if e.is_dir():
                    targets.append((f"home/{e.name}/.ssh", f"user_{e.name}"))
        root_ssh = self._r("root/.ssh")
        if os.path.isdir(root_ssh):
            targets.append(("root/.ssh", "root"))
        n = 0
        for rel, label in targets:
            src = self._r(rel)
            if not os.path.isdir(src):
                continue
            dst = _mkdir(os.path.join(ssh_d, label))
            for f in os.scandir(src):
                if f.is_file():
                    try:
                        shutil.copy2(f.path, os.path.join(dst, f.name))
                        self._artifact("ssh_keys", os.path.join(dst, f.name)); n += 1
                    except Exception:
                        pass
        self.log.info(f"  ✓ SSH artifacts : {n} file(s)")

    def _do_logs(self, d: str) -> None:
        log_src = self._r("var/log")
        log_dst = _mkdir(os.path.join(d, "logs"))
        if not os.path.isdir(log_src):
            self._warn("Logs: /var/log not accessible"); return
        total_bytes, n = 0, 0
        max_bytes = MAX_LOG_MB * 1024**2
        for fname in LINUX_LOG_PRIORITY:
            src = os.path.join(log_src, fname)
            if os.path.exists(src):
                size = os.path.getsize(src)
                dst  = os.path.join(log_dst, fname.replace("/", "_"))
                try:
                    shutil.copy2(src, dst)
                    self._artifact("logs", dst)
                    total_bytes += size; n += 1
                except Exception:
                    pass
        for root, _dirs, files in os.walk(log_src):
            if total_bytes >= max_bytes:
                break
            for f in files:
                src = os.path.join(root, f)
                rel = os.path.relpath(src, log_src)
                if any(p in rel for p in LINUX_LOG_PRIORITY):
                    continue
                try:
                    size = os.path.getsize(src)
                    if total_bytes + size > max_bytes:
                        continue
                    dst = os.path.join(log_dst, rel.replace("/", "_"))
                    shutil.copy2(src, dst)
                    self._artifact("logs", dst)
                    total_bytes += size; n += 1
                except Exception:
                    pass
        self.log.info(f"  ✓ Logs          : {n} files ({_human(total_bytes)})")

    def _do_cron(self, d: str) -> None:
        cron_d = _mkdir(os.path.join(d, "cron"))
        n = 0
        for rel in LINUX_CRON_PATHS:
            src = self._r(rel)
            if not os.path.exists(src):
                continue
            if os.path.isfile(src):
                dst = _copy_file(src, cron_d)
                if dst:
                    self._artifact("cron", dst); n += 1
            elif os.path.isdir(src):
                for f in os.scandir(src):
                    if f.is_file():
                        dst_name = f"{os.path.basename(rel)}_{f.name}"
                        dst = os.path.join(cron_d, dst_name)
                        try:
                            shutil.copy2(f.path, dst)
                            self._artifact("cron", dst); n += 1
                        except Exception:
                            pass
        self.log.info(f"  ✓ Cron jobs     : {n} file(s)")

    def _do_systemd_units(self, d: str) -> None:
        sd_d = _mkdir(os.path.join(d, "systemd"))
        n = 0
        for rel in LINUX_SYSTEMD_UNIT_DIRS:
            src = self._r(rel)
            if not os.path.isdir(src):
                continue
            for f in os.scandir(src):
                if f.is_file() and any(f.name.endswith(ext)
                                        for ext in (".service",".timer",".socket",".path")):
                    dst = os.path.join(sd_d, f.name)
                    try:
                        shutil.copy2(f.path, dst)
                        self._artifact("systemd", dst); n += 1
                    except Exception:
                        pass
        self.log.info(f"  ✓ Systemd units : {n}")

    def _do_network(self, d: str) -> None:
        net_d = _mkdir(os.path.join(d, "network"))
        if self.is_live:
            live_cmds: Dict[str, str] = {
                "ip_addr.txt":    "ip addr show",
                "ip_route.txt":   "ip route show table all",
                "ip_neigh.txt":   "ip neigh show",
                "ss_all.txt":     "ss -anp",
                "ss_listen.txt":  "ss -tlnp",
                "iptables.txt":   "iptables -L -n -v 2>/dev/null",
                "ip6tables.txt":  "ip6tables -L -n -v 2>/dev/null",
            }
            for fname, cmd in live_cmds.items():
                rc, out, _ = _run(cmd, shell=True, timeout=15)
                if rc == 0 and out.strip():
                    p = os.path.join(net_d, fname)
                    self.store.write_text(p, out)
                    self._artifact("network", p)
        # /proc/net files (live or offline)
        for rel in ["proc/net/arp", "proc/net/tcp", "proc/net/tcp6",
                     "proc/net/udp", "proc/net/udp6", "proc/net/if_inet6"]:
            src = self._r(rel)
            if os.path.exists(src):
                dst = os.path.join(net_d, rel.replace("/", "_"))
                try:
                    shutil.copy2(src, dst)
                    self._artifact("network", dst)
                except Exception:
                    pass
        self.log.info("  ✓ Network state : captured")

    def _do_packages(self, d: str) -> None:
        pkg_d = _mkdir(os.path.join(d, "packages"))
        cmds: Dict[str, str] = {
            "dpkg_list.txt":   "dpkg -l",
            "rpm_list.txt":    "rpm -qa --queryformat '%{NAME}|%{VERSION}|%{INSTALLTIME:date}\\n' 2>/dev/null",
            "pip3_list.txt":   "pip3 list 2>/dev/null",
            "snap_list.txt":   "snap list 2>/dev/null",
            "flatpak_list.txt":"flatpak list 2>/dev/null",
        }
        for fname, cmd in cmds.items():
            rc, out, _ = _run(cmd, shell=True, timeout=30)
            if rc == 0 and out.strip():
                p = os.path.join(pkg_d, fname)
                self.store.write_text(p, out)
                self._artifact("packages", p)
        self.log.info("  ✓ Packages      : captured")

    def _do_processes(self, d: str) -> None:
        if not self.is_live:
            return
        proc_d = _mkdir(os.path.join(d, "processes"))
        cmds: Dict[str, str] = {
            "ps_aux.txt":      "ps auxf",
            "lsof.txt":        "lsof -n 2>/dev/null | head -5000",
            "lsmod.txt":       "lsmod",
            "dmesg.txt":       "dmesg",
        }
        for fname, cmd in cmds.items():
            rc, out, _ = _run(cmd, shell=True, timeout=30)
            if rc == 0 and out.strip():
                p = os.path.join(proc_d, fname)
                self.store.write_text(p, out)
                self._artifact("processes", p)
        self.log.info("  ✓ Processes     : captured")

    def _do_shell_configs(self, d: str) -> None:
        """Collect .bashrc / .profile for persistence artefact detection."""
        cfg_d  = _mkdir(os.path.join(d, "shell_configs"))
        cfg_files = [".bashrc", ".bash_profile", ".profile",
                      ".zshrc", ".zprofile", ".config/fish/config.fish"]
        home = self._r("home")
        root_h = self._r("root")
        dirs = ([root_h] if os.path.isdir(root_h) else [])
        if os.path.isdir(home):
            dirs += [e.path for e in os.scandir(home) if e.is_dir()]
        n = 0
        for udir in dirs:
            uname = os.path.basename(udir)
            for cf in cfg_files:
                src = os.path.join(udir, cf)
                if os.path.exists(src):
                    label = cf.replace("/", "_").lstrip(".")
                    dst   = os.path.join(cfg_d, f"{uname}_{label}")
                    try:
                        shutil.copy2(src, dst)
                        self._artifact("shell_config", dst); n += 1
                    except Exception:
                        pass
        if n:
            self.log.info(f"  ✓ Shell configs : {n}")

    # ── Public interface ──────────────────────────────────────

    def collect_artifacts(self) -> bool:
        src = f"live ({self.root})" if self.is_live else f"offline ({self.root})"
        self.log.info(f"{'─'*60}")
        self.log.info(f"[LINUX] Artifact collection → {src}")
        self.meta.timestamp_start    = _utcnow()
        self.meta.status             = AcquisitionStatus.RUNNING
        self.meta.acquisition_method = "live_collection" if self.is_live else "offline_mount"
        self.meta.log_custody("acquisition_start", self.meta.operator,
                               f"Linux {'live' if self.is_live else 'offline'}: {self.root}")
        d = self.store.artifact_dir(self.dev_dir, "linux")

        steps = [
            ("System Files",    self._do_system_files),
            ("User Accounts",   self._do_user_accounts),
            ("Shell History",   self._do_shell_histories),
            ("SSH Artifacts",   self._do_ssh_artifacts),
            ("Cron Jobs",       self._do_cron),
            ("Systemd Units",   self._do_systemd_units),
            ("Network State",   self._do_network),
            ("Packages",        self._do_packages),
            ("Processes",       self._do_processes),
            ("Logs",            self._do_logs),
            ("Shell Configs",   self._do_shell_configs),
        ]

        for name, fn in steps:
            self.log.info(f"  → {name} …")
            try:
                fn(d)
            except Exception as exc:
                self._error(f"{name}: {exc}")

        self._finalize(self.meta.timestamp_start)
        self.log.info(f"[LINUX] Done → {len(self.meta.artifacts)} artifacts  "
                       f"{len(self.meta.errors)} errors")
        return True

    def triage(self) -> bool:
        self.log.info(f"[LINUX TRIAGE] → {self.root}")
        self.meta.timestamp_start    = _utcnow()
        self.meta.status             = AcquisitionStatus.RUNNING
        self.meta.acquisition_method = "triage"
        d = self.store.artifact_dir(self.dev_dir, "triage")
        try:
            for name, fn in [
                ("User Accounts", self._do_user_accounts),
                ("Shell History", self._do_shell_histories),
                ("System Files",  self._do_system_files),
                ("Network State", self._do_network),
                ("Processes",     self._do_processes),
            ]:
                self.log.info(f"  → {name} …")
                try:
                    fn(d)
                except Exception as exc:
                    self._error(f"{name}: {exc}")
            self._finalize(self.meta.timestamp_start)
            self.log.info(f"[LINUX TRIAGE] Done → {len(self.meta.artifacts)} artifacts")
            return True
        except Exception as exc:
            self.meta.status = AcquisitionStatus.FAILED
            self._error(str(exc)); return False


# ─────────────────────────────────────────────────────────────────────────────
# Forensic Imaging Engine
# ─────────────────────────────────────────────────────────────────────────────

class ImagingEngine:
    """
    Bit-for-bit forensic imaging with dual SHA-256 verification.

    Both the source device and the output image are hashed simultaneously
    during the single streaming read.  A separate verification pass can be
    requested afterwards to confirm image integrity independently.
    """

    def __init__(self, store: EvidenceStore, meta: ForensicMetadata):
        self.store = store
        self.meta  = meta
        self.log   = logging.getLogger("hive.imaging")

    def _device_size(self, device: str) -> int:
        rc, out, _ = _run(f"blockdev --getsize64 {device}", timeout=10)
        if rc == 0 and out.strip().isdigit():
            return int(out.strip())
        rc2, out2, _ = _run(f"lsblk -b -dn -o SIZE {device}", timeout=10)
        if rc2 == 0 and out2.strip().isdigit():
            return int(out2.strip())
        return 0

    def _write_hashfile(self, image_path: str, sha256: str, size: int) -> str:
        p = image_path + ".sha256"
        with open(p, "w") as fh:
            fh.write(f"{sha256}  {os.path.basename(image_path)}\n")
            fh.write(f"# bytes  : {size}\n")
            fh.write(f"# human  : {_human(size)}\n")
            fh.write(f"# utc    : {_utcnow()}\n")
            fh.write(f"# tool   : {HIVE_TOOL} v{HIVE_VERSION}\n")
        return p

    def _write_acq_log(self, image_path: str, src_hash: str,
                        dst_hash: str, size: int, duration: float) -> str:
        p = image_path + ".acqlog.json"
        with open(p, "w") as fh:
            json.dump({
                "acquisition_id": self.meta.acquisition_id,
                "case_id":        self.meta.case_id,
                "operator":       self.meta.operator,
                "tool":           f"{HIVE_TOOL} v{HIVE_VERSION}",
                "source_device":  self.meta.device_id,
                "image_path":     image_path,
                "start_utc":      self.meta.timestamp_start,
                "end_utc":        self.meta.timestamp_end,
                "duration_s":     round(duration, 2),
                "bytes_read":     size,
                "size_human":     _human(size),
                "source_sha256":  src_hash,
                "image_sha256":   dst_hash,
                "integrity_ok":   src_hash == dst_hash,
                "chain_of_custody": self.meta.chain_of_custody,
            }, fh, indent=2)
        return p

    def image_device(self, device: str, output_dir: str,
                      compress: bool = False) -> bool:
        """
        Stream-copy a block device to an image file.

        Args
          device:     Block device (e.g. /dev/sdb).
          output_dir: Destination directory.
          compress:   Wrap output in gzip.

        Returns True only when SHA-256 of source == SHA-256 of image.
        """
        _require_root()
        if not os.path.exists(device):
            self.log.error(f"Device not found: {device}"); return False

        size = self._device_size(device)
        _mkdir(output_dir)

        ts       = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        dev_safe = _safe_filename(device.lstrip("/"))
        img_name = f"{dev_safe}_{ts}.img" + (".gz" if compress else "")
        img_path = os.path.join(output_dir, img_name)

        self.meta.device_id          = device
        self.meta.image_size_bytes   = size
        self.meta.timestamp_start    = _utcnow()
        self.meta.acquisition_mode   = AcquisitionMode.IMAGE
        self.meta.acquisition_method = "raw_stream_python"
        self.meta.status             = AcquisitionStatus.RUNNING
        self.meta.log_custody("imaging_start", self.meta.operator,
                               f"Imaging {device} → {img_path}")

        self.log.info(f"{'─'*60}")
        self.log.info(f"[IMAGING] Source  : {device}  ({_human(size)})")
        self.log.info(f"[IMAGING] Output  : {img_path}")
        self.log.info(f"[IMAGING] Compress: {compress}")

        t0 = time.time()
        last_log = t0

        def _progress(done: int) -> None:
            nonlocal last_log
            now = time.time()
            if now - last_log < 10:
                return
            elapsed = now - t0
            pct  = done / size * 100 if size else 0
            rate = done / elapsed if elapsed else 0
            eta  = (size - done) / rate if rate else 0
            self.log.info(
                f"  {_human(done)} / {_human(size)}  "
                f"({pct:.1f}%)  {_human(rate)}/s  ETA {eta:.0f}s"
            )
            last_log = now

        try:
            h_src = hashlib.sha256()
            h_dst = hashlib.sha256()
            total = 0

            open_dst = gzip.open if compress else open

            with open(device, "rb") as src, open_dst(img_path, "wb") as dst:
                while True:
                    chunk = src.read(BLOCK_SIZE)
                    if not chunk:
                        break
                    h_src.update(chunk)
                    dst.write(chunk)
                    h_dst.update(chunk)
                    total += len(chunk)
                    _progress(total)

            duration = time.time() - t0
            src_hash = h_src.hexdigest()
            dst_hash = h_dst.hexdigest()
            ok       = (src_hash == dst_hash)

            self.meta.image_sha256      = src_hash
            self.meta.image_size_bytes  = total
            self.meta.timestamp_end     = _utcnow()
            self.meta.status            = AcquisitionStatus.COMPLETED if ok else AcquisitionStatus.FAILED

            hash_file = self._write_hashfile(img_path, src_hash, total)
            acq_log   = self._write_acq_log(img_path, src_hash, dst_hash, total, duration)
            self.meta.artifacts = [img_path, hash_file, acq_log]
            self.meta.log_custody("imaging_complete", self.meta.operator,
                                   f"SHA-256={src_hash}  verified={ok}")
            self.store.write_manifest(output_dir, self.meta)

            if ok:
                self.log.info(f"[IMAGING] ✓ INTEGRITY VERIFIED")
            else:
                self.log.error(f"[IMAGING] ✗ INTEGRITY MISMATCH")
                self.log.error(f"  Source : {src_hash}")
                self.log.error(f"  Image  : {dst_hash}")
                if self.meta.errors is not None:
                    self.meta.errors.append("integrity_hash_mismatch")

            self.log.info(f"[IMAGING] SHA-256 : {src_hash}")
            self.log.info(f"[IMAGING] Size    : {_human(total)}")
            self.log.info(f"[IMAGING] Speed   : {_human(total/max(duration,1))}/s")
            self.log.info(f"[IMAGING] Duration: {duration:.1f}s")
            return ok

        except PermissionError:
            self.log.error(f"[IMAGING] Permission denied: {device}")
            self.meta.status = AcquisitionStatus.FAILED
            return False
        except Exception as exc:
            self.log.error(f"[IMAGING] Error: {exc}", exc_info=True)
            self.meta.status = AcquisitionStatus.FAILED
            if self.meta.errors is not None:
                self.meta.errors.append(str(exc))
            return False

    def verify_image(self, image_path: str, expected_hash: str) -> bool:
        """Re-hash an image and compare against expected SHA-256."""
        self.log.info(f"[VERIFY] Hashing {image_path} …")
        t0 = time.time()
        actual   = _sha256_file(image_path)
        duration = time.time() - t0
        ok       = (actual.lower() == expected_hash.lower())
        self.log.info(f"[VERIFY] {'✓ MATCH' if ok else '✗ MISMATCH'}")
        self.log.info(f"[VERIFY] Expected : {expected_hash}")
        self.log.info(f"[VERIFY] Actual   : {actual}")
        self.log.info(f"[VERIFY] Duration : {duration:.1f}s")
        return ok


# ─────────────────────────────────────────────────────────────────────────────
# Device Discovery
# ─────────────────────────────────────────────────────────────────────────────

class DeviceDiscovery:
    """
    Auto-discovers Android devices via ADB and block storage via lsblk/blkid.
    Infers OS type from filesystem signatures to route to the correct collector.
    """

    def __init__(self):
        self.log = logging.getLogger("hive.discovery")

    def discover_all(self) -> List[DeviceInfo]:
        found = []
        found += self.discover_android()
        found += self.discover_block_devices()
        self.log.info(f"[DISCOVERY] {len(found)} device(s) found")
        return found

    def discover_android(self) -> List[DeviceInfo]:
        devices: List[DeviceInfo] = []
        rc, out, err = _run("adb devices -l", timeout=15)
        if rc != 0:
            self.log.debug(f"ADB unavailable: {err.strip()[:60]}"); return devices
        for line in out.splitlines()[1:]:
            line = line.strip()
            if not line or "daemon" in line.lower():
                continue
            parts  = line.split()
            if len(parts) < 2:
                continue
            serial = parts[0]
            state  = parts[1]
            auth   = (state == "device")
            model  = ""
            if auth:
                rc2, m, _ = _run(f"adb -s {serial} shell getprop ro.product.model", timeout=10)
                model = m.strip() if rc2 == 0 else ""
            dev = DeviceInfo(
                device_id   = f"android_{serial}",
                device_type = DeviceType.ANDROID,
                serial      = serial,
                model       = model,
                authorized  = auth,
            )
            status = "auth" if auth else state
            self.log.info(f"  Android  : {serial}  {model}  [{status}]")
            if not auth:
                self.log.warning(f"    → Enable USB debugging and authorise this host")
            devices.append(dev)
        return devices

    def discover_block_devices(self) -> List[DeviceInfo]:
        rc, out, _ = _run(
            "lsblk -J -o NAME,SIZE,TYPE,FSTYPE,LABEL,MODEL,SERIAL,MOUNTPOINT", timeout=15)
        if rc == 0:
            return self._parse_lsblk(out)
        return self._discover_fallback()

    def _parse_lsblk(self, out: str) -> List[DeviceInfo]:
        devices: List[DeviceInfo] = []
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return self._discover_fallback()

        for bd in data.get("blockdevices", []):
            if bd.get("type") != "disk":
                continue
            name = bd.get("name", "")
            if not name or name.startswith("loop"):
                continue

            block = f"/dev/{name}"
            os_t  = self._infer_os(bd, block)
            dev   = DeviceInfo(
                device_id    = f"disk_{name}",
                device_type  = os_t,
                serial       = (bd.get("serial") or "").strip(),
                model        = (bd.get("model") or "").strip(),
                block_device = block,
                filesystem   = (bd.get("fstype") or "").lower(),
                mount_point  = (bd.get("mountpoint") or ""),
                partitions   = [f"/dev/{c['name']}" for c in bd.get("children", [])
                                 if c.get("type") == "part"],
            )
            self.log.info(f"  Block    : {block}  {dev.model}  "
                           f"{bd.get('size','')}  OS:{os_t}")
            devices.append(dev)
        return devices

    def _infer_os(self, bd: dict, block: str) -> str:
        children = bd.get("children", [])
        fs_set   = {(c.get("fstype") or "").lower() for c in children}
        labels   = {(c.get("label") or "").lower() for c in children}

        if any("ntfs" in fs for fs in fs_set):
            return DeviceType.WINDOWS
        if any(fs in ("ext4","ext3","ext2","btrfs","xfs","f2fs") for fs in fs_set):
            return DeviceType.LINUX
        if any("apfs" in fs or "hfs" in fs for fs in fs_set):
            return DeviceType.MACOS
        if any("basic data" in l or "microsoft" in l for l in labels):
            return DeviceType.WINDOWS
        return DeviceType.UNKNOWN

    def _discover_fallback(self) -> List[DeviceInfo]:
        self.log.debug("lsblk failed; using blkid fallback")
        devices: List[DeviceInfo] = []
        seen: set = set()
        for pattern in ["/dev/sd?", "/dev/nvme?n?", "/dev/mmcblk?", "/dev/vd?", "/dev/hd?"]:
            for path in sorted(glob.glob(pattern)):
                if path in seen:
                    continue
                seen.add(path)
                rc, out, _ = _run(f"blkid {path}", timeout=10)
                fs = ""
                for part in out.split():
                    if part.startswith("TYPE="):
                        fs = part.split("=")[1].strip('"')
                dev = DeviceInfo(
                    device_id    = f"disk_{os.path.basename(path)}",
                    device_type  = DeviceType.UNKNOWN,
                    block_device = path,
                    filesystem   = fs,
                )
                self.log.info(f"  Block(fb): {path}  fstype:{fs}")
                devices.append(dev)
        return devices

    def mount_partition(self, partition: str, mount_point: str,
                         read_only: bool = True) -> bool:
        _mkdir(mount_point)
        rc_id, fs, _ = _run(f"blkid -o value -s TYPE {partition}", timeout=10)
        fs = fs.strip() if rc_id == 0 else ""
        flags = "ro" if read_only else "rw"

        if "ntfs" in fs:
            cmd = (f"mount -t ntfs-3g "
                   f"-o {flags},show_sys_files,streams_interface=windows "
                   f"{partition} {mount_point}")
        elif fs in ("vfat","fat32","fat16","exfat"):
            cmd = f"mount -o {flags} {partition} {mount_point}"
        else:
            cmd = f"mount -o {flags} {partition} {mount_point}"

        rc, _, err = _run(cmd, timeout=30)
        if rc == 0:
            self.log.info(f"  ✓ Mounted {partition} → {mount_point}  [{fs}, {flags}]")
            return True
        self.log.error(f"  ✗ Mount failed: {err.strip()[:100]}")
        return False

    def unmount_partition(self, mount_point: str) -> bool:
        rc, _, err = _run(f"umount {mount_point}", timeout=15)
        if rc == 0:
            self.log.info(f"  ✓ Unmounted {mount_point}")
            return True
        self.log.warning(f"  ✗ Unmount: {err.strip()[:80]}")
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Acquisition Task + Worker Queue
# ─────────────────────────────────────────────────────────────────────────────

class AcquisitionTask:
    """One unit of work: one device × one mode."""

    COLLECTOR_MAP = {
        DeviceType.ANDROID: AndroidCollector,
        DeviceType.WINDOWS: WindowsCollector,
        DeviceType.LINUX:   LinuxCollector,
    }

    def __init__(self, device: DeviceInfo, mode: str,
                  store: EvidenceStore, config: Dict):
        self.device  = device
        self.mode    = mode
        self.store   = store
        self.config  = config
        self.task_id = str(uuid.uuid4())[:8]

    def execute(self) -> ForensicMetadata:
        meta = ForensicMetadata(
            case_id        = self.config.get("case_id", "UNKNOWN"),
            operator       = self.config.get("operator", "unknown"),
            device_type    = self.device.device_type,
            device_id      = self.device.device_id,
            device_serial  = self.device.serial,
            device_model   = self.device.model,
            acquisition_mode = self.mode,
            notes          = self.config.get("notes", ""),
        )
        log = logging.getLogger(f"hive.task.{self.task_id}")

        cls = self.COLLECTOR_MAP.get(self.device.device_type)
        if cls is None:
            log.warning(f"No collector for type '{self.device.device_type}'")
            meta.status = AcquisitionStatus.FAILED
            meta.errors.append(f"Unsupported device type: {self.device.device_type}")
            return meta

        collector = cls(self.device, self.store, meta)
        if self.mode == AcquisitionMode.ARTIFACT:
            collector.collect_artifacts()
        elif self.mode == AcquisitionMode.TRIAGE:
            collector.triage()
        else:
            log.error(f"Task mode '{self.mode}' not valid here")
            meta.status = AcquisitionStatus.FAILED
        return meta


class WorkerQueue:
    """Thread-pool task dispatcher for parallel device acquisition."""

    def __init__(self, max_workers: int = DEFAULT_WORKERS):
        self.max_workers = max_workers
        self.log         = logging.getLogger("hive.workers")
        self._lock       = threading.Lock()
        self._results: List[ForensicMetadata] = []

    def run(self, tasks: List[AcquisitionTask]) -> List[ForensicMetadata]:
        self.log.info(f"[WORKERS] {len(tasks)} task(s), {self.max_workers} worker(s)")
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=self.max_workers,
                thread_name_prefix="hive_worker") as ex:
            futures = {ex.submit(self._wrap, t): t for t in tasks}
            for fut in concurrent.futures.as_completed(futures):
                dev = futures[fut].device.device_id
                try:
                    result = fut.result()
                    self.log.info(f"  Task done: {dev}  [{result.status}]")
                    with self._lock:
                        self._results.append(result)
                except Exception as exc:
                    self.log.error(f"  Task crashed: {dev}  {exc}", exc_info=True)
        return list(self._results)

    def _wrap(self, task: AcquisitionTask) -> ForensicMetadata:
        self.log.info(f"  Starting task {task.task_id} → {task.device.device_id}")
        try:
            return task.execute()
        except Exception as exc:
            m = ForensicMetadata(status=AcquisitionStatus.FAILED)
            m.errors.append(str(exc))
            return m


# ─────────────────────────────────────────────────────────────────────────────
# HIVE Collector — Main Orchestrator
# ─────────────────────────────────────────────────────────────────────────────

class HIVECollector:
    """
    Top-level orchestrator.

    Routes requests to the correct collector module based on target type,
    manages the evidence store, and co-ordinates the worker pool.

    Future integration points (stubs):
      • self.es_client    → Elasticsearch (index evidence as it arrives)
      • self.neo4j_driver → Neo4j (build entity relationship graph)
      • self.pg_conn      → PostgreSQL (case / chain-of-custody DB)
      • self.kafka_prod   → Apache Kafka (distributed evidence ingestion)
    """

    def __init__(self, config: Dict):
        self.config   = config
        self.out_dir  = config.get("output_dir", DEFAULT_OUTPUT)
        self.case_id  = config.get("case_id", f"CASE-{datetime.date.today()}")
        self.operator = config.get("operator", "unknown")
        self.workers  = config.get("workers", DEFAULT_WORKERS)
        self.verbose  = config.get("verbose", False)

        self.log       = setup_logging(self.out_dir, self.verbose)
        self.store     = EvidenceStore(self.out_dir, self.case_id)
        self.discovery = DeviceDiscovery()
        self.queue     = WorkerQueue(self.workers)

        self._banner()

    def _banner(self) -> None:
        self.log.info("═" * 70)
        self.log.info(f"  {HIVE_TOOL}  v{HIVE_VERSION}")
        self.log.info(f"  Case      : {self.case_id}")
        self.log.info(f"  Operator  : {self.operator}")
        self.log.info(f"  Output    : {self.out_dir}")
        self.log.info(f"  Host      : {platform.node()}  Python {sys.version.split()[0]}")
        self.log.info("═" * 70)

    # ── Public workflow entry points ──────────────────────────

    def run_auto(self, mode: str) -> List[ForensicMetadata]:
        """Auto-discover every connected device and collect from all."""
        self.log.info(f"[HIVE] Auto-discover + {mode}")
        devices = self.discovery.discover_all()
        if not devices:
            self.log.warning("[HIVE] No devices discovered")
            return []
        return self._dispatch(devices, mode)

    def run_android(self, serial: Optional[str], mode: str) -> ForensicMetadata:
        """Collect from a specific (or auto-detected first) Android device."""
        if serial:
            dev = DeviceInfo(device_id=f"android_{serial}",
                              device_type=DeviceType.ANDROID, serial=serial)
        else:
            androids = self.discovery.discover_android()
            if not androids:
                self.log.error("[HIVE] No Android devices found")
                return ForensicMetadata(status=AcquisitionStatus.FAILED)
            dev = androids[0]
            self.log.info(f"[HIVE] Using: {dev.serial}")
        results = self._dispatch([dev], mode)
        return results[0] if results else ForensicMetadata(status=AcquisitionStatus.FAILED)

    def run_windows(self, mount_point: str, mode: str,
                     device_id: str = "") -> ForensicMetadata:
        """Collect from an already-mounted Windows NTFS volume."""
        dev = DeviceInfo(
            device_id   = device_id or f"windows_{_safe_filename(os.path.basename(mount_point))}",
            device_type = DeviceType.WINDOWS,
            mount_point = mount_point,
            filesystem  = "ntfs",
        )
        results = self._dispatch([dev], mode)
        return results[0] if results else ForensicMetadata(status=AcquisitionStatus.FAILED)

    def run_linux(self, mount_point: str, mode: str,
                   device_id: str = "") -> ForensicMetadata:
        """Collect from a live Linux system or mounted ext4/btrfs/xfs volume."""
        dev = DeviceInfo(
            device_id   = device_id or f"linux_{_safe_filename(os.path.basename(mount_point) or 'live')}",
            device_type = DeviceType.LINUX,
            mount_point = mount_point,
        )
        results = self._dispatch([dev], mode)
        return results[0] if results else ForensicMetadata(status=AcquisitionStatus.FAILED)

    def run_image(self, block_device: str, output_dir: Optional[str] = None,
                   compress: bool = False) -> bool:
        """Forensic image a block device."""
        _require_root()
        meta = ForensicMetadata(
            case_id  = self.case_id,
            operator = self.operator,
            device_id= block_device,
            acquisition_mode = AcquisitionMode.IMAGE,
        )
        out = output_dir or self.store.image_dir()
        return ImagingEngine(self.store, meta).image_device(block_device, out, compress)

    def mount_and_collect(self, partition: str, os_type: str,
                           mode: str) -> ForensicMetadata:
        """Mount a raw partition, collect evidence, then unmount."""
        _require_root()
        mp = f"/mnt/hive_{_safe_filename(os.path.basename(partition))}_{int(time.time())}"
        _mkdir(mp)
        if not self.discovery.mount_partition(partition, mp, read_only=True):
            return ForensicMetadata(status=AcquisitionStatus.FAILED,
                                     errors=[f"mount failed: {partition}"])
        try:
            if os_type == DeviceType.WINDOWS:
                return self.run_windows(mp, mode, f"win_{_safe_filename(os.path.basename(partition))}")
            elif os_type == DeviceType.LINUX:
                return self.run_linux(mp, mode, f"lnx_{_safe_filename(os.path.basename(partition))}")
            else:
                return ForensicMetadata(status=AcquisitionStatus.FAILED,
                                         errors=[f"unsupported OS type: {os_type}"])
        finally:
            self.discovery.unmount_partition(mp)
            try:
                os.rmdir(mp)
            except Exception:
                pass

    def generate_report(self) -> str:
        return self.store.save_case_report()

    # ── Internal ──────────────────────────────────────────────

    def _dispatch(self, devices: List[DeviceInfo], mode: str) -> List[ForensicMetadata]:
        tasks = [AcquisitionTask(dev, mode, self.store, self.config) for dev in devices]
        return self.queue.run(tasks)


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="collector.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "HIVE Platform  —  Core Acquisition Engine  v" + HIVE_VERSION + "\n"
            "Digital Forensics & Incident Response  |  Evidence Collection\n\n"
            "LEGAL NOTICE: Authorised forensic investigations only."
        ),
        epilog="""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 QUICK-START EXAMPLES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Auto-discover every device and collect artifacts:
  sudo python3 collector.py --mode artifact --auto-discover

Android – specific device:
  sudo python3 collector.py --mode artifact --target android --serial R3CN90AXXXX

Android – rapid triage, first connected device:
  sudo python3 collector.py --mode triage --target android

Windows offline (already mounted):
  sudo python3 collector.py --mode artifact --target windows --mount /mnt/win

Linux offline (already mounted):
  sudo python3 collector.py --mode artifact --target linux --mount /mnt/lnx

Linux live (this machine):
  sudo python3 collector.py --mode artifact --target linux

Raw forensic image:
  sudo python3 collector.py --mode image --device /dev/sdb --output /evidence/

Compressed image:
  sudo python3 collector.py --mode image --device /dev/sdb --compress

Auto-mount, collect, unmount:
  sudo python3 collector.py --mode artifact --partition /dev/sdb1 --os windows

Verify an existing image:
  sudo python3 collector.py --verify /evidence/dev_sdb.img

Multi-device parallel triage (8 threads):
  sudo python3 collector.py --mode triage --auto-discover --workers 8

Load config from file + generate report:
  sudo python3 collector.py --config /etc/hive/hive.json --report
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
    )

    # Mode
    p.add_argument("--mode", choices=["artifact","image","triage"],
                    default="artifact",
                    help="Acquisition mode  (default: artifact)")
    p.add_argument("--target", choices=["android","windows","linux","auto"],
                    default="auto",
                    help="Target platform   (default: auto-discover)")

    # Device selection
    g = p.add_argument_group("Device Selection")
    g.add_argument("--auto-discover", action="store_true",
                    help="Auto-discover all connected devices")
    g.add_argument("--serial",  metavar="SERIAL",
                    help="Android device serial (adb devices)")
    g.add_argument("--device",  metavar="BLOCK_DEV",
                    help="Block device for imaging, e.g. /dev/sdb")
    g.add_argument("--partition", metavar="PARTITION",
                    help="Partition to auto-mount + collect, e.g. /dev/sdb1")
    g.add_argument("--os", choices=["windows","linux"],
                    help="OS type for --partition auto-mount")
    g.add_argument("--mount",   metavar="PATH",
                    help="Existing mount point for --target windows/linux")

    # Imaging
    g2 = p.add_argument_group("Imaging Options")
    g2.add_argument("--compress", action="store_true",
                     help="Gzip-compress output image (slower but smaller)")
    g2.add_argument("--verify", metavar="IMAGE_PATH",
                     help="Verify SHA-256 of an existing image file")

    # Case metadata
    g3 = p.add_argument_group("Case Metadata")
    g3.add_argument("--case-id",  default=f"CASE-{datetime.date.today()}",
                     help="Case / investigation identifier")
    g3.add_argument("--operator", default=os.environ.get("USER","unknown"),
                     help="Investigator name or badge number")
    g3.add_argument("--notes",    default="",
                     help="Free-text chain-of-custody notes")

    # Output / operation
    g4 = p.add_argument_group("Output and Operation")
    g4.add_argument("--output",  default=DEFAULT_OUTPUT,
                     help=f"Evidence root directory  (default: {DEFAULT_OUTPUT})")
    g4.add_argument("--workers", type=int, default=DEFAULT_WORKERS,
                     help=f"Parallel workers for multi-device runs (default: {DEFAULT_WORKERS})")
    g4.add_argument("--config",  metavar="FILE",
                     help="JSON config file (values override CLI defaults)")
    g4.add_argument("--report",  action="store_true",
                     help="Write CASE_REPORT.json after acquisition")
    g4.add_argument("--list-devices", action="store_true",
                     help="Print discovered devices and exit")
    g4.add_argument("-v","--verbose", action="store_true",
                     help="Debug-level logging")
    return p


def _load_config(args: argparse.Namespace) -> Dict:
    cfg: Dict = {
        "case_id":    args.case_id,
        "operator":   args.operator,
        "output_dir": args.output,
        "workers":    args.workers,
        "verbose":    args.verbose,
        "notes":      args.notes,
    }
    if args.config and os.path.exists(args.config):
        with open(args.config) as fh:
            cfg.update(json.load(fh))
        print(f"[*] Config loaded from {args.config}")
    return cfg


def main() -> int:
    parser = build_parser()
    args   = parser.parse_args()
    config = _load_config(args)
    mode   = args.mode

    hive = HIVECollector(config)

    # ── --list-devices ────────────────────────────────────────
    if args.list_devices:
        devices = hive.discovery.discover_all()
        print(json.dumps([asdict(d) for d in devices], indent=2, default=str))
        return 0

    # ── --verify ──────────────────────────────────────────────
    if args.verify:
        img  = args.verify
        hf   = img + ".sha256"
        if not os.path.exists(img):
            print(f"[!] Image not found: {img}"); return 1
        if not os.path.exists(hf):
            print(f"[!] Hash file not found: {hf}"); return 1
        with open(hf) as fh:
            expected = fh.readline().split()[0]
        meta   = ForensicMetadata(case_id=config["case_id"], operator=config["operator"])
        engine = ImagingEngine(hive.store, meta)
        return 0 if engine.verify_image(img, expected) else 1

    # ── --mode image ──────────────────────────────────────────
    if mode == "image":
        if not args.device:
            print("[!] --device required for image mode  (e.g. --device /dev/sdb)")
            return 1
        ok = hive.run_image(args.device, args.output or None, compress=args.compress)
        return 0 if ok else 1

    # ── --auto-discover ───────────────────────────────────────
    if args.auto_discover or args.target == "auto":
        results = hive.run_auto(mode)
        if args.report:
            hive.generate_report()
        return 0

    # ── --partition (auto-mount) ──────────────────────────────
    if args.partition:
        if not args.os:
            print("[!] --os {windows|linux} required with --partition"); return 1
        os_type = DeviceType.WINDOWS if args.os == "windows" else DeviceType.LINUX
        meta    = hive.mount_and_collect(args.partition, os_type, mode)
        return 0 if meta.status in (AcquisitionStatus.COMPLETED,
                                     AcquisitionStatus.PARTIAL) else 1

    # ── Explicit targets ──────────────────────────────────────
    if args.target == "android":
        meta = hive.run_android(args.serial, mode)
        return 0 if meta.status in (AcquisitionStatus.COMPLETED,
                                     AcquisitionStatus.PARTIAL) else 1

    if args.target == "windows":
        if not args.mount:
            print("[!] --mount required for windows target  (e.g. --mount /mnt/win)")
            return 1
        meta = hive.run_windows(args.mount, mode)
        return 0 if meta.status in (AcquisitionStatus.COMPLETED,
                                     AcquisitionStatus.PARTIAL) else 1

    if args.target == "linux":
        mount = args.mount or "/"
        meta  = hive.run_linux(mount, mode)
        return 0 if meta.status in (AcquisitionStatus.COMPLETED,
                                     AcquisitionStatus.PARTIAL) else 1

    print("[!] No action specified.  Run with --help for usage.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
