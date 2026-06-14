#!/usr/bin/env python3
"""
parser.py  —  HIVE Platform · Stage 2: Universal Evidence Parser
═══════════════════════════════════════════════════════════════════════════════
High-scale Investigation and Verification Engine  (HIVE)  v1.0.0

Automatically identifies, parses, and normalises every artifact collected by
collector.py regardless of source platform, producing a unified SQLite evidence
database ready for correlator.py.

Supported artifact platforms
  • Android   — SMS, call logs, contacts, installed apps, browser, calendar,
                MMS, media index, device properties, logcat, accounts, wifi
  • Windows   — Registry hives, EVTX event logs, prefetch, browser SQLite,
                user accounts, recent/LNK files, scheduled tasks, file listing
  • Linux     — passwd/shadow, auth.log, shell history, SSH keys/config,
                cron jobs, systemd units, network state, package inventory,
                process listing, syslog

Intelligence extraction (all platforms)
  Phone numbers, email addresses, IPv4/IPv6, domains, URLs, MD5/SHA1/SHA256
  hashes, BTC/ETH wallet addresses, MAC addresses, IMEI numbers, Android
  package names, usernames, Wi-Fi SSIDs.

Timeline
  Every timestamp-bearing record is normalised to UTC ISO-8601 and inserted
  into a chronological timeline table for correlator consumption.

Output
  <evidence_root>/<case_id>/
    hive_evidence.db   — SQLite evidence database
    PARSER_REPORT.json — run summary

Pipeline position
  collector.py → [parser.py] → correlator.py → visualiser.py

Optional dependencies (graceful fallback if absent)
  python-evtx   (pip install python-evtx)    — Windows EVTX parsing
  python-registry (pip install python-registry) — Windows Registry parsing

Usage:
  python3 parser.py --evidence /evidence --case-id CASE-2024-001
  python3 parser.py --evidence /evidence --case-id CASE-2024-001 --workers 8
  python3 parser.py --device-dir /evidence/CASE-2024-001/android_ABC123_a1b2
  python3 parser.py --evidence /evidence --case-id CASE-2024-001 --export-json
═══════════════════════════════════════════════════════════════════════════════
"""

from __future__ import annotations

import os
import re
import sys
import json
import uuid
import sqlite3
import logging
import argparse
import datetime
import hashlib
import threading
import concurrent.futures
from abc         import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from pathlib     import Path
from typing      import Optional, List, Dict, Any, Tuple, Iterator

# ── Optional third-party imports (graceful degradation) ──────────────────────
try:
    import Evtx.Evtx as _evtx_lib                    # pip install python-evtx
    import xml.etree.ElementTree as _ET
    HAS_EVTX = True
except ImportError:
    HAS_EVTX = False

try:
    import Registry.Registry as _reg_lib             # pip install python-registry
    HAS_REGISTRY = True
except ImportError:
    HAS_REGISTRY = False

# ─────────────────────────────────────────────────────────────────────────────
# Constants & Version
# ─────────────────────────────────────────────────────────────────────────────

HIVE_PARSER_VERSION = "1.0.0"
HIVE_TOOL           = "HIVE-parser"
LOG_FMT             = "[%(asctime)s] %(levelname)-8s %(name)s — %(message)s"
DATE_FMT            = "%Y-%m-%dT%H:%M:%SZ"
DEFAULT_WORKERS     = 4
SNIPPET_WIDTH       = 100          # chars of surrounding context for entities
MAX_READ_BYTES      = 50_000_000   # 50 MB max per text file

# Chrome timestamp epoch (Jan 1, 1601 microseconds)
_CHROME_EPOCH = datetime.datetime(1601, 1, 1)

# Syslog month abbreviations
_SYSLOG_MONTHS = {
    "jan":1,"feb":2,"mar":3,"apr":4,"may":5,"jun":6,
    "jul":7,"aug":8,"sep":9,"oct":10,"nov":11,"dec":12,
}

# ─────────────────────────────────────────────────────────────────────────────
# Regex Patterns — Entity Extraction
# ─────────────────────────────────────────────────────────────────────────────

# Phone: E.164 and local formats, 7–15 digits
_RE_PHONE      = re.compile(r'(?<!\d)(\+?[1-9]\d{6,14})(?!\d)')
# Email
_RE_EMAIL      = re.compile(r'\b([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b')
# IPv4 (octet-bounded)
_RE_IPV4       = re.compile(
    r'\b((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?))\b')
# IPv6 (simplified)
_RE_IPV6       = re.compile(
    r'\b((?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}|::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{0,4})\b')
# URLs
_RE_URL        = re.compile(r'(https?://[^\s<>"\'\]\[,;(){}\|]+)', re.I)
# Domain (common TLDs only to cut noise)
_RE_DOMAIN     = re.compile(
    r'\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:'
    r'com|net|org|io|gov|edu|mil|co|uk|de|fr|ru|cn|jp|nl|br|au|ca|'
    r'info|biz|me|tv|cc|xyz|onion|tor|app|dev|ai|cloud|store|shop))\b', re.I)
# Hashes
_RE_HASH_MD5   = re.compile(r'\b([0-9a-fA-F]{32})\b')
_RE_HASH_SHA1  = re.compile(r'\b([0-9a-fA-F]{40})\b')
_RE_HASH_SHA256= re.compile(r'\b([0-9a-fA-F]{64})\b')
# Cryptocurrency
_RE_BTC        = re.compile(
    r'\b((?:1|3)[a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[ac-hj-np-z02-9]{11,71})\b')
_RE_ETH        = re.compile(r'\b(0x[a-fA-F0-9]{40})\b')
# MAC address
_RE_MAC        = re.compile(r'\b((?:[0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2})\b')
# IMEI (15 contiguous digits)
_RE_IMEI       = re.compile(r'(?<!\d)(\d{15})(?!\d)')
# Android package names (e.g. com.example.app)
_RE_PACKAGE    = re.compile(r'\b([a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){2,})\b')

# Linux auth.log patterns
_RE_SSH_OK     = re.compile(
    r'(\w{3}\s+\d+\s+[\d:]+)\s+(\S+)\s+sshd\[\d+\]:\s+Accepted\s+(\w+)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)')
_RE_SSH_FAIL   = re.compile(
    r'(\w{3}\s+\d+\s+[\d:]+)\s+(\S+)\s+sshd\[\d+\]:\s+Failed\s+\w+\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)')
_RE_SSH_INVAL  = re.compile(
    r'(\w{3}\s+\d+\s+[\d:]+)\s+(\S+)\s+sshd\[\d+\]:\s+Invalid user\s+(\S+)\s+from\s+(\S+)')
_RE_SUDO       = re.compile(
    r'(\w{3}\s+\d+\s+[\d:]+)\s+(\S+)\s+sudo\[\d+\]:\s+(\S+)\s+:.*?COMMAND=(.*)')
_RE_SESSION    = re.compile(
    r'(\w{3}\s+\d+\s+[\d:]+)\s+(\S+)\s+\S+\[\d+\]:\s+pam_unix.*?session (opened|closed) for user (\S+)')

# Private/loopback IP ranges (often filtered in entity extraction)
_PRIVATE_IP_RE = re.compile(
    r'^(?:127\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|0\.0\.0\.0$|::1$|fe80:)', re.I)

# ─────────────────────────────────────────────────────────────────────────────
# Artifact & Entity Type Namespaces
# ─────────────────────────────────────────────────────────────────────────────

class ArtifactType:
    # Android
    ANDROID_SMS          = "android_sms"
    ANDROID_CALL_LOG     = "android_call_log"
    ANDROID_CONTACTS     = "android_contacts"
    ANDROID_APPS         = "android_apps"
    ANDROID_APPS_DUMP    = "android_apps_dump"
    ANDROID_BROWSER      = "android_browser"
    ANDROID_CALENDAR     = "android_calendar"
    ANDROID_MMS          = "android_mms"
    ANDROID_DOWNLOADS    = "android_downloads"
    ANDROID_MEDIA        = "android_media"
    ANDROID_DEVICE_PROPS = "android_device_props"
    ANDROID_LOGCAT       = "android_logcat"
    ANDROID_ACCOUNTS     = "android_accounts"
    ANDROID_WIFI         = "android_wifi"
    ANDROID_NETWORK      = "android_network_state"
    ANDROID_PROCESSES    = "android_processes"
    # Windows
    WIN_REGISTRY         = "windows_registry"
    WIN_EVTX             = "windows_evtx"
    WIN_PREFETCH         = "windows_prefetch"
    WIN_BROWSER_CHROME   = "windows_browser_chrome"
    WIN_BROWSER_FIREFOX  = "windows_browser_firefox"
    WIN_BROWSER_EDGE     = "windows_browser_edge"
    WIN_USER_ACCOUNTS    = "windows_user_accounts"
    WIN_RECENT_FILES     = "windows_recent_files"
    WIN_SCHEDULED_TASKS  = "windows_scheduled_tasks"
    WIN_FILE_LISTING     = "windows_file_listing"
    WIN_SYSTEM_INFO      = "windows_system_info"
    WIN_SPECIAL_FILES    = "windows_special_files"
    WIN_USB              = "windows_usb_history"
    # Linux
    LINUX_PASSWD         = "linux_passwd"
    LINUX_SHADOW         = "linux_shadow"
    LINUX_GROUP          = "linux_group"
    LINUX_SUDOERS        = "linux_sudoers"
    LINUX_AUTH_LOG       = "linux_auth_log"
    LINUX_SYSLOG         = "linux_syslog"
    LINUX_SHELL_HISTORY  = "linux_shell_history"
    LINUX_SSH_ARTIFACT   = "linux_ssh_artifact"
    LINUX_SSH_KEY        = "linux_ssh_private_key"
    LINUX_CRON           = "linux_cron"
    LINUX_SYSTEMD        = "linux_systemd_unit"
    LINUX_NETWORK        = "linux_network_state"
    LINUX_PACKAGES       = "linux_packages"
    LINUX_PROCESSES      = "linux_processes"
    # Generic
    MANIFEST             = "manifest"
    SYSTEM_INFO          = "system_info"
    ACCOUNTS_SUMMARY     = "accounts_summary"
    UNKNOWN              = "unknown"


class EntityType:
    PHONE       = "PHONE"
    EMAIL       = "EMAIL"
    IPV4        = "IPV4"
    IPV6        = "IPV6"
    DOMAIN      = "DOMAIN"
    URL         = "URL"
    HASH_MD5    = "HASH_MD5"
    HASH_SHA1   = "HASH_SHA1"
    HASH_SHA256 = "HASH_SHA256"
    CRYPTO_BTC  = "CRYPTO_BTC"
    CRYPTO_ETH  = "CRYPTO_ETH"
    MAC_ADDR    = "MAC_ADDRESS"
    IMEI        = "IMEI"
    USERNAME    = "USERNAME"
    PACKAGE     = "ANDROID_PACKAGE"
    WIFI_SSID   = "WIFI_SSID"
    ANDROID_ID  = "ANDROID_ID"
    FILE_PATH   = "FILE_PATH"


class EventType:
    SMS_SENT       = "SMS_SENT"
    SMS_RECEIVED   = "SMS_RECEIVED"
    CALL_OUTGOING  = "CALL_OUTGOING"
    CALL_INCOMING  = "CALL_INCOMING"
    CALL_MISSED    = "CALL_MISSED"
    CALL_VOICEMAIL = "CALL_VOICEMAIL"
    BROWSER_VISIT  = "BROWSER_VISIT"
    DOWNLOAD       = "DOWNLOAD"
    LOGIN_SUCCESS  = "LOGIN_SUCCESS"
    LOGIN_FAILED   = "LOGIN_FAILED"
    SUDO_CMD       = "SUDO_COMMAND"
    SHELL_CMD      = "SHELL_COMMAND"
    USB_CONNECTED  = "USB_CONNECTED"
    APP_INSTALLED  = "APP_INSTALLED"
    USER_LOGON     = "USER_LOGON"
    USER_LOGOFF    = "USER_LOGOFF"
    PROCESS_CREATED= "PROCESS_CREATED"
    SERVICE_EVENT  = "SERVICE_EVENT"
    ACCOUNT_EVENT  = "ACCOUNT_EVENT"
    CRON_JOB       = "CRON_JOB"
    WIFI_JOIN      = "WIFI_JOIN"
    FILE_ACCESS    = "FILE_ACCESSED"
    MEDIA_EVENT    = "MEDIA_EVENT"
    CALENDAR_EVENT = "CALENDAR_EVENT"
    MMS_MESSAGE    = "MMS_MESSAGE"

# ─────────────────────────────────────────────────────────────────────────────
# Artifact filename → type mapping
# ─────────────────────────────────────────────────────────────────────────────

_FILENAME_MAP: Dict[str, str] = {
    # Android (content-provider text format)
    "sms.txt":              ArtifactType.ANDROID_SMS,
    "call_log.txt":         ArtifactType.ANDROID_CALL_LOG,
    "contacts.txt":         ArtifactType.ANDROID_CONTACTS,
    "apps_user.txt":        ArtifactType.ANDROID_APPS,
    "apps_all.txt":         ArtifactType.ANDROID_APPS,
    "packages_dump.txt":    ArtifactType.ANDROID_APPS_DUMP,
    "calendar_events.txt":  ArtifactType.ANDROID_CALENDAR,
    "mms.txt":              ArtifactType.ANDROID_MMS,
    "downloads_db.txt":     ArtifactType.ANDROID_DOWNLOADS,
    "download_files_listing.txt": ArtifactType.ANDROID_DOWNLOADS,
    "media_images.txt":     ArtifactType.ANDROID_MEDIA,
    "media_videos.txt":     ArtifactType.ANDROID_MEDIA,
    "device_props.txt":     ArtifactType.ANDROID_DEVICE_PROPS,
    "logcat.txt":           ArtifactType.ANDROID_LOGCAT,
    "accounts_dumpsys.txt": ArtifactType.ANDROID_ACCOUNTS,
    "processes.txt":        ArtifactType.ANDROID_PROCESSES,
    "running_processes.txt":ArtifactType.ANDROID_PROCESSES,
    "ip_addr.txt":          ArtifactType.ANDROID_NETWORK,
    "network_interfaces.txt":ArtifactType.ANDROID_NETWORK,
    # Windows (binary hives parsed separately)
    "SAM":                  ArtifactType.WIN_REGISTRY,
    "SYSTEM":               ArtifactType.WIN_REGISTRY,
    "SOFTWARE":             ArtifactType.WIN_REGISTRY,
    "SECURITY":             ArtifactType.WIN_REGISTRY,
    "DEFAULT":              ArtifactType.WIN_REGISTRY,
    "NTUSER.DAT":           ArtifactType.WIN_REGISTRY,
    "UsrClass.dat":         ArtifactType.WIN_REGISTRY,
    "user_accounts.json":   ArtifactType.WIN_USER_ACCOUNTS,
    "system_info.json":     ArtifactType.WIN_SYSTEM_INFO,
    "special_files.json":   ArtifactType.WIN_SPECIAL_FILES,
    "file_listing.tsv":     ArtifactType.WIN_FILE_LISTING,
    "setupapi.dev.log":     ArtifactType.WIN_USB,
    # Linux (standard filenames)
    "passwd":               ArtifactType.LINUX_PASSWD,
    "shadow":               ArtifactType.LINUX_SHADOW,
    "group":                ArtifactType.LINUX_GROUP,
    "sudoers":              ArtifactType.LINUX_SUDOERS,
    "auth.log":             ArtifactType.LINUX_AUTH_LOG,
    "auth.log.1":           ArtifactType.LINUX_AUTH_LOG,
    "secure":               ArtifactType.LINUX_AUTH_LOG,
    "syslog":               ArtifactType.LINUX_SYSLOG,
    "syslog.1":             ArtifactType.LINUX_SYSLOG,
    "messages":             ArtifactType.LINUX_SYSLOG,
    "kern.log":             ArtifactType.LINUX_SYSLOG,
    "dpkg_list.txt":        ArtifactType.LINUX_PACKAGES,
    "rpm_list.txt":         ArtifactType.LINUX_PACKAGES,
    "pip3_list.txt":        ArtifactType.LINUX_PACKAGES,
    "snap_list.txt":        ArtifactType.LINUX_PACKAGES,
    "flatpak_list.txt":     ArtifactType.LINUX_PACKAGES,
    "ps_aux.txt":           ArtifactType.LINUX_PROCESSES,
    "lsmod.txt":            ArtifactType.LINUX_PROCESSES,
    "ss_all.txt":           ArtifactType.LINUX_NETWORK,
    "ss_listen.txt":        ArtifactType.LINUX_NETWORK,
    "ip_route.txt":         ArtifactType.LINUX_NETWORK,
    "ip_neigh.txt":         ArtifactType.LINUX_NETWORK,
    "iptables.txt":         ArtifactType.LINUX_NETWORK,
    "connections.txt":      ArtifactType.LINUX_NETWORK,
    "accounts_summary.json":ArtifactType.ACCOUNTS_SUMMARY,
    "MANIFEST.json":        ArtifactType.MANIFEST,
}

# Extension-based detection
_EXT_MAP: Dict[str, str] = {
    ".evtx": ArtifactType.WIN_EVTX,
    ".pf":   ArtifactType.WIN_PREFETCH,
    ".lnk":  ArtifactType.WIN_RECENT_FILES,
}

# Substring pattern detection (checked against lowercase filename)
_SUBSTR_MAP: List[Tuple[str, str]] = [
    ("shell_history",     ArtifactType.LINUX_SHELL_HISTORY),
    ("bash_history",      ArtifactType.LINUX_SHELL_HISTORY),
    ("zsh_history",       ArtifactType.LINUX_SHELL_HISTORY),
    ("authorized_keys",   ArtifactType.LINUX_SSH_ARTIFACT),
    ("known_hosts",       ArtifactType.LINUX_SSH_ARTIFACT),
    ("id_rsa.pub",        ArtifactType.LINUX_SSH_ARTIFACT),
    ("id_ed25519.pub",    ArtifactType.LINUX_SSH_ARTIFACT),
    ("id_ecdsa.pub",      ArtifactType.LINUX_SSH_ARTIFACT),
    ("id_rsa",            ArtifactType.LINUX_SSH_KEY),
    ("id_ed25519",        ArtifactType.LINUX_SSH_KEY),
    ("id_ecdsa",          ArtifactType.LINUX_SSH_KEY),
    ("sshd_config",       ArtifactType.LINUX_SSH_ARTIFACT),
    (".service",          ArtifactType.LINUX_SYSTEMD),
    (".timer",            ArtifactType.LINUX_SYSTEMD),
    (".socket",           ArtifactType.LINUX_SYSTEMD),
    (".path",             ArtifactType.LINUX_SYSTEMD),
    ("crontab",           ArtifactType.LINUX_CRON),
    ("cron.",             ArtifactType.LINUX_CRON),
    ("cron_",             ArtifactType.LINUX_CRON),
    ("chrome_history",    ArtifactType.WIN_BROWSER_CHROME),
    ("edge_history",      ArtifactType.WIN_BROWSER_EDGE),
    ("history",           ArtifactType.WIN_BROWSER_CHROME),  # Chrome / Edge History DB
    ("places.sqlite",     ArtifactType.WIN_BROWSER_FIREFOX),
    ("apps_user",         ArtifactType.ANDROID_APPS),
    ("installed_apps",    ArtifactType.ANDROID_APPS),
]

# ─────────────────────────────────────────────────────────────────────────────
# Data Models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ParsedRecord:
    """One normalised evidence record from any artifact type / platform."""
    record_id:      str            = field(default_factory=lambda: str(uuid.uuid4()))
    case_id:        str            = ""
    device_id:      str            = ""
    acquisition_id: str            = ""
    platform:       str            = ""
    artifact_type:  str            = ArtifactType.UNKNOWN
    source_file:    str            = ""
    timestamp_utc:  str            = ""
    timestamp_raw:  str            = ""
    event_type:     str            = ""
    content:        Dict[str, Any] = field(default_factory=dict)
    raw_text:       str            = ""
    parser_version: str            = HIVE_PARSER_VERSION
    confidence:     float          = 1.0


@dataclass
class ExtractedEntity:
    """An IOC or investigative identifier extracted from a parsed record."""
    entity_id:    str   = field(default_factory=lambda: str(uuid.uuid4()))
    artifact_id:  str   = ""
    device_id:    str   = ""
    case_id:      str   = ""
    entity_type:  str   = ""
    entity_value: str   = ""
    context:      str   = ""
    source_file:  str   = ""
    artifact_type:str   = ""
    first_seen:   str   = ""
    confidence:   float = 1.0


@dataclass
class TimelineEvent:
    """A chronological event entry built from any artifact."""
    event_id:      str            = field(default_factory=lambda: str(uuid.uuid4()))
    case_id:       str            = ""
    device_id:     str            = ""
    artifact_id:   str            = ""
    timestamp_utc: str            = ""
    event_type:    str            = ""
    description:   str            = ""
    actor:         str            = ""
    target:        str            = ""
    metadata:      Dict[str, Any] = field(default_factory=dict)
    source_file:   str            = ""


@dataclass
class ParserResult:
    """Summary produced at the end of a parsing run."""
    run_id:          str            = field(default_factory=lambda: str(uuid.uuid4()))
    case_id:         str            = ""
    db_path:         str            = ""
    started_at:      str            = ""
    completed_at:    str            = ""
    devices_parsed:  int            = 0
    files_processed: int            = 0
    records_parsed:  int            = 0
    entities_found:  int            = 0
    timeline_events: int            = 0
    errors:          List[str]      = field(default_factory=list)
    warnings:        List[str]      = field(default_factory=list)
    artifact_counts: Dict[str, int] = field(default_factory=dict)


# ─────────────────────────────────────────────────────────────────────────────
# Utility Functions
# ─────────────────────────────────────────────────────────────────────────────

def _utcnow() -> str:
    return datetime.datetime.utcnow().strftime(DATE_FMT)


def _read_text(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(MAX_READ_BYTES)
    except Exception:
        return None


def _read_json(path: str) -> Optional[Any]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def _snippet(text: str, pos: int) -> str:
    """Return surrounding text snippet for entity context."""
    s = max(0, pos - SNIPPET_WIDTH // 2)
    e = min(len(text), pos + SNIPPET_WIDTH // 2)
    return text[s:e].replace("\n", " ").strip()


def _unix_ms(ms_val: Any) -> str:
    """Unix milliseconds → UTC ISO."""
    try:
        dt = datetime.datetime.utcfromtimestamp(int(ms_val) / 1000)
        return dt.strftime(DATE_FMT)
    except Exception:
        return ""


def _unix_s(s_val: Any) -> str:
    """Unix seconds → UTC ISO."""
    try:
        dt = datetime.datetime.utcfromtimestamp(int(s_val))
        return dt.strftime(DATE_FMT)
    except Exception:
        return ""


def _chrome_ts(chrome_val: Any) -> str:
    """Chrome microseconds since 1601-01-01 → UTC ISO."""
    try:
        dt = _CHROME_EPOCH + datetime.timedelta(microseconds=int(chrome_val))
        return dt.strftime(DATE_FMT)
    except Exception:
        return ""


def _firefox_ts(firefox_val: Any) -> str:
    """Firefox microseconds since Unix epoch → UTC ISO."""
    try:
        dt = datetime.datetime.utcfromtimestamp(int(firefox_val) / 1_000_000)
        return dt.strftime(DATE_FMT)
    except Exception:
        return ""


def _syslog_ts(ts_str: str, year: int = 0) -> str:
    """'Jun 14 10:23:45' → UTC ISO."""
    try:
        parts = ts_str.split()
        if len(parts) < 3:
            return ""
        mon = _SYSLOG_MONTHS.get(parts[0].lower(), 0)
        if not mon:
            return ""
        day = int(parts[1])
        h, m, s = [int(x) for x in parts[2].split(":")]
        yr  = year or datetime.datetime.utcnow().year
        return datetime.datetime(yr, mon, day, h, m, s).strftime(DATE_FMT)
    except Exception:
        return ""


def _iso_ts(ts_str: str) -> str:
    """Best-effort normalisation of various ISO-ish timestamp strings."""
    if not ts_str:
        return ""
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ",
                 "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S",
                 "%Y/%m/%d %H:%M:%S", "%d/%b/%Y:%H:%M:%S"):
        try:
            dt = datetime.datetime.strptime(ts_str.strip()[:26], fmt)
            return dt.strftime(DATE_FMT)
        except Exception:
            pass
    return ""


def _parse_content_row(line: str) -> Dict[str, str]:
    """
    Parse one ADB content-provider output row.

    Input:  "Row: 0 _id=1, address=+447911, body=Hello, how are you?, date=1640000, type=1"
    Output: {"_id": "1", "address": "+447911", "body": "Hello, how are you?",
             "date": "1640000", "type": "1"}

    Values may contain commas; we split on the pattern ", fieldname=" which is
    a reliable boundary in content-provider output.
    """
    content = re.sub(r"^Row:\s*\d+\s*", "", line.strip())
    if not content or "=" not in content:
        return {}

    # Collect (position_of_separator, field_name, value_start_pos)
    starts: List[Tuple[int, str, int]] = []
    m0 = re.match(r"(\w+)=", content)
    if m0:
        starts.append((0, m0.group(1), m0.end()))
    for m in re.finditer(r",\s*(\w+)=", content):
        starts.append((m.start(), m.group(1), m.end()))

    result: Dict[str, str] = {}
    for i, (_, key, val_start) in enumerate(starts):
        val_end = starts[i + 1][0] if i + 1 < len(starts) else len(content)
        result[key] = content[val_start:val_end].strip()
    return result


def _setup_logging(output_dir: str, verbose: bool = False) -> logging.Logger:
    os.makedirs(output_dir, exist_ok=True)
    log_path = os.path.join(output_dir, f"hive_parser_{datetime.date.today()}.log")
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
    return logging.getLogger("hive.parser")


# ─────────────────────────────────────────────────────────────────────────────
# Evidence Database
# ─────────────────────────────────────────────────────────────────────────────

class EvidenceDatabase:
    """
    Thread-safe SQLite evidence store.  Serves as the canonical output of
    parser.py and the primary input for correlator.py.

    Schema
      devices   — one row per acquired device (from MANIFEST.json)
      artifacts — one row per parsed evidence record
      entities  — extracted IOCs / identifiers (many per artifact)
      timeline  — normalised chronological events
      errors    — parse failures for investigator review
    """

    DDL = """
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous   = NORMAL;
    PRAGMA foreign_keys  = ON;

    CREATE TABLE IF NOT EXISTS devices (
        device_id      TEXT PRIMARY KEY,
        case_id        TEXT NOT NULL,
        device_type    TEXT,
        device_model   TEXT,
        device_os      TEXT,
        acquisition_id TEXT,
        manifest_json  TEXT,
        created_at     TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
    );

    CREATE TABLE IF NOT EXISTS artifacts (
        record_id      TEXT PRIMARY KEY,
        case_id        TEXT NOT NULL,
        device_id      TEXT NOT NULL,
        acquisition_id TEXT,
        platform       TEXT,
        artifact_type  TEXT NOT NULL,
        source_file    TEXT,
        timestamp_utc  TEXT,
        timestamp_raw  TEXT,
        event_type     TEXT,
        content        TEXT,
        raw_text       TEXT,
        parser_version TEXT,
        confidence     REAL DEFAULT 1.0,
        FOREIGN KEY (device_id) REFERENCES devices(device_id)
    );

    CREATE TABLE IF NOT EXISTS entities (
        entity_id     TEXT PRIMARY KEY,
        artifact_id   TEXT NOT NULL,
        device_id     TEXT NOT NULL,
        case_id       TEXT NOT NULL,
        entity_type   TEXT NOT NULL,
        entity_value  TEXT NOT NULL,
        context       TEXT,
        source_file   TEXT,
        artifact_type TEXT,
        first_seen    TEXT,
        confidence    REAL DEFAULT 1.0,
        FOREIGN KEY (artifact_id) REFERENCES artifacts(record_id)
    );

    CREATE TABLE IF NOT EXISTS timeline (
        event_id      TEXT PRIMARY KEY,
        case_id       TEXT NOT NULL,
        device_id     TEXT NOT NULL,
        artifact_id   TEXT,
        timestamp_utc TEXT NOT NULL,
        event_type    TEXT NOT NULL,
        description   TEXT,
        actor         TEXT,
        target        TEXT,
        metadata      TEXT,
        source_file   TEXT,
        FOREIGN KEY (artifact_id) REFERENCES artifacts(record_id)
    );

    CREATE TABLE IF NOT EXISTS parse_errors (
        error_id     TEXT PRIMARY KEY,
        case_id      TEXT,
        device_id    TEXT,
        source_file  TEXT,
        artifact_type TEXT,
        error_msg    TEXT,
        created_at   TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
    );

    CREATE INDEX IF NOT EXISTS idx_art_device   ON artifacts(device_id);
    CREATE INDEX IF NOT EXISTS idx_art_type     ON artifacts(artifact_type);
    CREATE INDEX IF NOT EXISTS idx_art_ts       ON artifacts(timestamp_utc);
    CREATE INDEX IF NOT EXISTS idx_art_case     ON artifacts(case_id);
    CREATE INDEX IF NOT EXISTS idx_ent_tv       ON entities(entity_type, entity_value);
    CREATE INDEX IF NOT EXISTS idx_ent_device   ON entities(device_id);
    CREATE INDEX IF NOT EXISTS idx_ent_case     ON entities(case_id);
    CREATE INDEX IF NOT EXISTS idx_tl_ts        ON timeline(timestamp_utc);
    CREATE INDEX IF NOT EXISTS idx_tl_device    ON timeline(device_id);
    CREATE INDEX IF NOT EXISTS idx_tl_case      ON timeline(case_id);
    CREATE INDEX IF NOT EXISTS idx_tl_type      ON timeline(event_type);
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._lock   = threading.Lock()
        self._conn   = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.executescript(self.DDL)
        self._conn.commit()
        self.log = logging.getLogger("hive.db")

    def _exec(self, sql: str, params: tuple = ()) -> None:
        with self._lock:
            try:
                self._conn.execute(sql, params)
                self._conn.commit()
            except sqlite3.Error as exc:
                self.log.error(f"DB error: {exc}  SQL: {sql[:80]}")

    def _exec_many(self, sql: str, rows: List[tuple]) -> None:
        if not rows:
            return
        with self._lock:
            try:
                self._conn.executemany(sql, rows)
                self._conn.commit()
            except sqlite3.Error as exc:
                self.log.error(f"DB executemany error: {exc}")

    def upsert_device(self, manifest: Dict) -> None:
        self._exec(
            "INSERT OR REPLACE INTO devices "
            "(device_id,case_id,device_type,device_model,device_os,"
            " acquisition_id,manifest_json) VALUES (?,?,?,?,?,?,?)",
            (manifest.get("device_id",""),
             manifest.get("case_id",""),
             manifest.get("device_type",""),
             manifest.get("device_model",""),
             manifest.get("device_os",""),
             manifest.get("acquisition_id",""),
             json.dumps(manifest)))

    def insert_artifact(self, r: ParsedRecord) -> None:
        self._exec(
            "INSERT OR IGNORE INTO artifacts "
            "(record_id,case_id,device_id,acquisition_id,platform,"
            " artifact_type,source_file,timestamp_utc,timestamp_raw,"
            " event_type,content,raw_text,parser_version,confidence) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (r.record_id, r.case_id, r.device_id, r.acquisition_id,
             r.platform, r.artifact_type, r.source_file,
             r.timestamp_utc, r.timestamp_raw, r.event_type,
             json.dumps(r.content, default=str), r.raw_text[:2000],
             r.parser_version, r.confidence))

    def insert_artifacts_bulk(self, records: List[ParsedRecord]) -> None:
        rows = [
            (r.record_id, r.case_id, r.device_id, r.acquisition_id,
             r.platform, r.artifact_type, r.source_file,
             r.timestamp_utc, r.timestamp_raw, r.event_type,
             json.dumps(r.content, default=str), r.raw_text[:2000],
             r.parser_version, r.confidence)
            for r in records
        ]
        self._exec_many(
            "INSERT OR IGNORE INTO artifacts "
            "(record_id,case_id,device_id,acquisition_id,platform,"
            " artifact_type,source_file,timestamp_utc,timestamp_raw,"
            " event_type,content,raw_text,parser_version,confidence) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)

    def insert_entities_bulk(self, entities: List[ExtractedEntity]) -> None:
        rows = [
            (e.entity_id, e.artifact_id, e.device_id, e.case_id,
             e.entity_type, e.entity_value, e.context,
             e.source_file, e.artifact_type, e.first_seen, e.confidence)
            for e in entities
        ]
        self._exec_many(
            "INSERT OR IGNORE INTO entities "
            "(entity_id,artifact_id,device_id,case_id,entity_type,"
            " entity_value,context,source_file,artifact_type,"
            " first_seen,confidence) VALUES (?,?,?,?,?,?,?,?,?,?,?)", rows)

    def insert_timeline_bulk(self, events: List[TimelineEvent]) -> None:
        rows = [
            (e.event_id, e.case_id, e.device_id, e.artifact_id,
             e.timestamp_utc, e.event_type, e.description,
             e.actor, e.target, json.dumps(e.metadata, default=str),
             e.source_file)
            for e in events
        ]
        self._exec_many(
            "INSERT OR IGNORE INTO timeline "
            "(event_id,case_id,device_id,artifact_id,timestamp_utc,"
            " event_type,description,actor,target,metadata,source_file) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)", rows)

    def log_error(self, case_id: str, device_id: str,
                   source_file: str, artifact_type: str, msg: str) -> None:
        self._exec(
            "INSERT INTO parse_errors "
            "(error_id,case_id,device_id,source_file,artifact_type,error_msg) "
            "VALUES (?,?,?,?,?,?)",
            (str(uuid.uuid4()), case_id, device_id, source_file, artifact_type, msg))

    def stats(self) -> Dict[str, int]:
        with self._lock:
            cur = self._conn.cursor()
            result = {}
            for tbl in ("devices","artifacts","entities","timeline","parse_errors"):
                cur.execute(f"SELECT COUNT(*) FROM {tbl}")
                result[tbl] = cur.fetchone()[0]
        return result

    def export_json(self, output_dir: str) -> List[str]:
        """Export each table as a JSON Lines file for downstream consumption."""
        os.makedirs(output_dir, exist_ok=True)
        paths = []
        tables = ["devices", "artifacts", "entities", "timeline", "parse_errors"]
        with self._lock:
            cur = self._conn.cursor()
            for tbl in tables:
                path = os.path.join(output_dir, f"{tbl}.jsonl")
                cur.execute(f"SELECT * FROM {tbl}")
                cols = [d[0] for d in cur.description]
                with open(path, "w", encoding="utf-8") as fh:
                    for row in cur.fetchall():
                        fh.write(json.dumps(dict(zip(cols, row))) + "\n")
                paths.append(path)
        return paths

    def close(self) -> None:
        with self._lock:
            self._conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# Entity Extractor
# ─────────────────────────────────────────────────────────────────────────────

class EntityExtractor:
    """
    Scans arbitrary text for entities of investigative value.

    Each extracted entity carries a context snippet, source file, artifact
    type, and confidence score so analysts can assess relevance.
    """

    def extract(self, text: str, artifact_id: str, device_id: str,
                 case_id: str, source_file: str,
                 artifact_type: str, first_seen: str = "") -> List[ExtractedEntity]:
        if not text:
            return []
        results: List[ExtractedEntity] = []
        seen: set = set()  # deduplicate (type, value) per artifact

        def _add(etype: str, value: str, pos: int, conf: float = 1.0) -> None:
            key = (etype, value.lower())
            if key in seen:
                return
            seen.add(key)
            results.append(ExtractedEntity(
                artifact_id   = artifact_id,
                device_id     = device_id,
                case_id       = case_id,
                entity_type   = etype,
                entity_value  = value,
                context       = _snippet(text, pos),
                source_file   = source_file,
                artifact_type = artifact_type,
                first_seen    = first_seen or _utcnow(),
                confidence    = conf,
            ))

        # URLs (before domains — longer pattern)
        for m in _RE_URL.finditer(text):
            _add(EntityType.URL, m.group(1), m.start())

        # Emails
        for m in _RE_EMAIL.finditer(text):
            _add(EntityType.EMAIL, m.group(1).lower(), m.start())

        # SHA-256 (longest hash first to avoid MD5/SHA1 submatches)
        for m in _RE_HASH_SHA256.finditer(text):
            _add(EntityType.HASH_SHA256, m.group(1).lower(), m.start())

        # SHA-1
        for m in _RE_HASH_SHA1.finditer(text):
            v = m.group(1).lower()
            if not any(e.entity_value == v for e in results
                        if e.entity_type == EntityType.HASH_SHA256):
                _add(EntityType.HASH_SHA1, v, m.start())

        # MD5
        for m in _RE_HASH_MD5.finditer(text):
            v = m.group(1).lower()
            if len(v) == 32:
                _add(EntityType.HASH_MD5, v, m.start(), conf=0.8)

        # Ethereum
        for m in _RE_ETH.finditer(text):
            _add(EntityType.CRYPTO_ETH, m.group(1), m.start())

        # Bitcoin
        for m in _RE_BTC.finditer(text):
            _add(EntityType.CRYPTO_BTC, m.group(1), m.start())

        # IPv4
        for m in _RE_IPV4.finditer(text):
            ip = m.group(1)
            conf = 0.7 if _PRIVATE_IP_RE.match(ip) else 1.0
            _add(EntityType.IPV4, ip, m.start(), conf=conf)

        # IPv6
        for m in _RE_IPV6.finditer(text):
            _add(EntityType.IPV6, m.group(1).lower(), m.start(), conf=0.9)

        # Domains (skip those already captured as part of a URL or email)
        url_spans  = {(m.start(), m.end()) for m in _RE_URL.finditer(text)}
        mail_spans = {(m.start(), m.end()) for m in _RE_EMAIL.finditer(text)}
        for m in _RE_DOMAIN.finditer(text):
            inside = any(s <= m.start() and m.end() <= e
                         for s, e in url_spans | mail_spans)
            if not inside:
                _add(EntityType.DOMAIN, m.group(1).lower(), m.start(), conf=0.8)

        # MAC addresses
        for m in _RE_MAC.finditer(text):
            _add(EntityType.MAC_ADDR, m.group(1).lower(), m.start())

        # Phone numbers (7–15 digits, exclude already-matched IMEIs)
        for m in _RE_PHONE.finditer(text):
            v = re.sub(r"\s", "", m.group(1))
            if len(v) >= 7:
                _add(EntityType.PHONE, v, m.start(), conf=0.85)

        # IMEI (exactly 15 digits)
        for m in _RE_IMEI.finditer(text):
            _add(EntityType.IMEI, m.group(1), m.start())

        # Android packages (reduce noise: only com.*, net.*, org.* prefixes)
        if artifact_type.startswith("android_"):
            for m in _RE_PACKAGE.finditer(text):
                v = m.group(1)
                if v.startswith(("com.","net.","org.","io.","uk.","de.")):
                    _add(EntityType.PACKAGE, v, m.start(), conf=0.9)

        return results


# ─────────────────────────────────────────────────────────────────────────────
# Artifact Type Detector
# ─────────────────────────────────────────────────────────────────────────────

class ArtifactDetector:
    """
    Determines the ArtifactType of an arbitrary file using a three-stage
    strategy:
      1. Exact filename match
      2. File extension match
      3. Substring pattern in filename
      4. Directory context (artifacts/android/, artifacts/windows/, etc.)
      5. Content signature (first 20 lines)
    """

    def detect(self, file_path: str) -> str:
        name  = os.path.basename(file_path)
        lower = name.lower()
        ext   = os.path.splitext(name)[1].lower()

        # Stage 1 – exact name
        if name in _FILENAME_MAP:
            return _FILENAME_MAP[name]

        # Stage 2 – extension
        if ext in _EXT_MAP:
            return _EXT_MAP[ext]

        # Stage 3 – substring
        for substr, atype in _SUBSTR_MAP:
            if substr in lower:
                return atype

        # Stage 4 – directory context
        parts = Path(file_path).parts
        if "android" in parts:
            return self._from_content_android(file_path)
        if "windows" in parts or "registry" in parts or "event_logs" in parts:
            return ArtifactType.UNKNOWN
        if "linux" in parts:
            return self._from_content_linux(file_path)

        # Stage 5 – content signature
        return self._from_content(file_path)

    def _from_content_android(self, path: str) -> str:
        text = _read_text(path)
        if not text:
            return ArtifactType.UNKNOWN
        head = text[:500]
        if "Row:" in head and "address=" in head:
            return ArtifactType.ANDROID_SMS
        if "Row:" in head and "duration=" in head:
            return ArtifactType.ANDROID_CALL_LOG
        if "Row:" in head and "display_name=" in head:
            return ArtifactType.ANDROID_CONTACTS
        if "package:" in head or "apk" in head.lower():
            return ArtifactType.ANDROID_APPS
        if "ro.product" in head or "ro.build" in head:
            return ArtifactType.ANDROID_DEVICE_PROPS
        return ArtifactType.UNKNOWN

    def _from_content_linux(self, path: str) -> str:
        text = _read_text(path)
        if not text:
            return ArtifactType.UNKNOWN
        head = text[:500]
        if re.search(r"\w+:x:\d+:\d+:", head):
            return ArtifactType.LINUX_PASSWD
        if re.search(r"sshd\[\d+\]|sudo\[\d+\]", head):
            return ArtifactType.LINUX_AUTH_LOG
        if re.search(r"^(ssh-rsa|ssh-ed25519|ecdsa-sha)", head, re.M):
            return ArtifactType.LINUX_SSH_ARTIFACT
        return ArtifactType.UNKNOWN

    def _from_content(self, path: str) -> str:
        """Last resort: quick content signature check."""
        try:
            with open(path, "rb") as fh:
                header = fh.read(16)
            # SQLite magic
            if header.startswith(b"SQLite format 3"):
                return ArtifactType.WIN_BROWSER_CHROME
            # EVTX magic
            if header.startswith(b"ElfFile\x00"):
                return ArtifactType.WIN_EVTX
        except Exception:
            pass
        return ArtifactType.UNKNOWN


# ─────────────────────────────────────────────────────────────────────────────
# Base Platform Parser
# ─────────────────────────────────────────────────────────────────────────────

class BasePlatformParser(ABC):
    """Abstract base for Android / Windows / Linux parsers."""

    PLATFORM = "unknown"

    def __init__(self, device_id: str, case_id: str,
                  acquisition_id: str, extractor: EntityExtractor):
        self.device_id      = device_id
        self.case_id        = case_id
        self.acquisition_id = acquisition_id
        self.extractor      = extractor
        self.log            = logging.getLogger(f"hive.parser.{self.PLATFORM}")

    def _base_record(self, artifact_type: str, source_file: str) -> ParsedRecord:
        return ParsedRecord(
            case_id        = self.case_id,
            device_id      = self.device_id,
            acquisition_id = self.acquisition_id,
            platform       = self.PLATFORM,
            artifact_type  = artifact_type,
            source_file    = source_file,
            parser_version = HIVE_PARSER_VERSION,
        )

    def _tl(self, artifact_id: str, ts: str, etype: str,
             desc: str, source: str,
             actor: str = "", target: str = "",
             meta: Optional[Dict] = None) -> Optional[TimelineEvent]:
        if not ts:
            return None
        return TimelineEvent(
            case_id       = self.case_id,
            device_id     = self.device_id,
            artifact_id   = artifact_id,
            timestamp_utc = ts,
            event_type    = etype,
            description   = desc,
            actor         = actor,
            target        = target,
            metadata      = meta or {},
            source_file   = source,
        )

    @abstractmethod
    def parse(self, file_path: str,
               artifact_type: str) -> Tuple[List[ParsedRecord],
                                             List[ExtractedEntity],
                                             List[TimelineEvent]]:
        """Return (records, entities, timeline_events) for one file."""


# ─────────────────────────────────────────────────────────────────────────────
# Android Parser
# ─────────────────────────────────────────────────────────────────────────────

class AndroidParser(BasePlatformParser):
    """Parses artifacts produced by AndroidCollector (ADB content-provider format)."""

    PLATFORM = "android"

    # Android call type codes
    _CALL_TYPES = {
        "1": EventType.CALL_INCOMING,
        "2": EventType.CALL_OUTGOING,
        "3": EventType.CALL_MISSED,
        "4": EventType.CALL_VOICEMAIL,
        "5": EventType.CALL_INCOMING,   # rejected
    }

    def parse(self, file_path: str, artifact_type: str):
        dispatch = {
            ArtifactType.ANDROID_SMS:         self._sms,
            ArtifactType.ANDROID_CALL_LOG:    self._call_log,
            ArtifactType.ANDROID_CONTACTS:    self._contacts,
            ArtifactType.ANDROID_APPS:        self._apps,
            ArtifactType.ANDROID_APPS_DUMP:   self._apps_dump,
            ArtifactType.ANDROID_CALENDAR:    self._calendar,
            ArtifactType.ANDROID_MMS:         self._mms,
            ArtifactType.ANDROID_DOWNLOADS:   self._downloads,
            ArtifactType.ANDROID_MEDIA:       self._media,
            ArtifactType.ANDROID_DEVICE_PROPS:self._device_props,
            ArtifactType.ANDROID_LOGCAT:      self._logcat,
            ArtifactType.ANDROID_ACCOUNTS:    self._accounts,
            ArtifactType.ANDROID_WIFI:        self._wifi,
            ArtifactType.ANDROID_NETWORK:     self._network,
            ArtifactType.ANDROID_PROCESSES:   self._processes,
        }
        fn = dispatch.get(artifact_type)
        if fn is None:
            return [], [], []
        try:
            return fn(file_path)
        except Exception as exc:
            self.log.error(f"Android parse error [{artifact_type}] {file_path}: {exc}")
            return [], [], []

    # ── Content-row helpers ───────────────────────────────────

    def _iter_rows(self, text: str) -> Iterator[Dict[str, str]]:
        for line in text.splitlines():
            if line.startswith("Row:"):
                parsed = _parse_content_row(line)
                if parsed:
                    yield parsed

    def _entities_from_row(self, row: Dict[str, str], record_id: str,
                             source: str, atype: str,
                             ts: str = "") -> List[ExtractedEntity]:
        text = " ".join(str(v) for v in row.values())
        return self.extractor.extract(text, record_id, self.device_id,
                                       self.case_id, source, atype, ts)

    # ── Individual artifact parsers ───────────────────────────

    def _sms(self, path: str):
        text = _read_text(path)
        if not text:
            return [], [], []
        records, entities, timeline = [], [], []

        for row in self._iter_rows(text):
            ts  = _unix_ms(row.get("date", 0))
            typ = row.get("type", "")
            r   = self._base_record(ArtifactType.ANDROID_SMS, path)
            r.timestamp_utc = ts
            r.timestamp_raw = row.get("date", "")
            r.event_type    = EventType.SMS_SENT if typ == "2" else EventType.SMS_RECEIVED
            r.content = {
                "address":  row.get("address", ""),
                "body":     row.get("body", ""),
                "type":     typ,
                "read":     row.get("read", ""),
                "thread_id":row.get("thread_id", ""),
                "service_center": row.get("service_center", ""),
            }
            r.raw_text = row.get("body", "")[:500]
            records.append(r)
            entities.extend(self._entities_from_row(row, r.record_id, path,
                                                      ArtifactType.ANDROID_SMS, ts))
            peer = row.get("address", "")
            desc = f"SMS {'sent to' if typ=='2' else 'received from'} {peer}"
            ev = self._tl(r.record_id, ts, r.event_type, desc[:200], path,
                           actor=self.device_id if typ == "2" else peer,
                           target=peer if typ == "2" else self.device_id,
                           meta={"chars": len(row.get("body",""))})
            if ev:
                timeline.append(ev)

        self.log.info(f"  SMS: {len(records)} messages")
        return records, entities, timeline

    def _call_log(self, path: str):
        text = _read_text(path)
        if not text:
            return [], [], []
        records, entities, timeline = [], [], []

        for row in self._iter_rows(text):
            ts     = _unix_ms(row.get("date", 0))
            ctype  = row.get("type", "")
            dur    = row.get("duration", "0")
            number = row.get("number", row.get("number_presentation", ""))
            name   = row.get("name", row.get("cachedName", ""))

            r = self._base_record(ArtifactType.ANDROID_CALL_LOG, path)
            r.timestamp_utc = ts
            r.timestamp_raw = row.get("date", "")
            r.event_type    = self._CALL_TYPES.get(ctype, EventType.CALL_INCOMING)
            r.content = {
                "number":       number,
                "name":         name,
                "duration_s":   int(dur) if dur.isdigit() else 0,
                "type":         ctype,
            }
            records.append(r)
            entities.extend(self._entities_from_row(row, r.record_id, path,
                                                      ArtifactType.ANDROID_CALL_LOG, ts))
            ctype_label = {
                "1":"INCOMING","2":"OUTGOING","3":"MISSED","4":"VOICEMAIL"
            }.get(ctype,"UNKNOWN")
            desc = f"{ctype_label} call {'to' if ctype=='2' else 'from'} {name or number}"
            ev = self._tl(r.record_id, ts, r.event_type, desc[:200], path,
                           actor=self.device_id if ctype == "2" else number,
                           target=number if ctype == "2" else self.device_id,
                           meta={"duration_s": r.content["duration_s"]})
            if ev:
                timeline.append(ev)

        self.log.info(f"  Call log: {len(records)} records")
        return records, entities, timeline

    def _contacts(self, path: str):
        text = _read_text(path)
        if not text:
            return [], [], []
        records, entities, timeline = [], [], []

        for row in self._iter_rows(text):
            r = self._base_record(ArtifactType.ANDROID_CONTACTS, path)
            r.content = {
                "display_name": row.get("display_name", ""),
                "number":       row.get("number", ""),
                "type":         row.get("type", ""),
                "email":        row.get("data1", ""),
            }
            records.append(r)
            entities.extend(self._entities_from_row(row, r.record_id, path,
                                                      ArtifactType.ANDROID_CONTACTS))

        self.log.info(f"  Contacts: {len(records)}")
        return records, entities, timeline

    def _apps(self, path: str):
        text = _read_text(path)
        if not text:
            return [], [], []
        records, entities, timeline = [], [], []

        for line in text.splitlines():
            line = line.strip()
            if not line.startswith("package:"):
                continue
            parts = line.split("=")
            pkg  = parts[-1].strip() if len(parts) > 1 else line.replace("package:", "").split("apk")[0].strip()
            r    = self._base_record(ArtifactType.ANDROID_APPS, path)
            r.content  = {"package": pkg}
            r.raw_text = line
            records.append(r)
            entities.append(ExtractedEntity(
                artifact_id   = r.record_id,
                device_id     = self.device_id,
                case_id       = self.case_id,
                entity_type   = EntityType.PACKAGE,
                entity_value  = pkg,
                context       = line,
                source_file   = path,
                artifact_type = ArtifactType.ANDROID_APPS,
                confidence    = 1.0,
            ))
            ev = self._tl(r.record_id, _utcnow(), EventType.APP_INSTALLED,
                           f"App installed: {pkg}", path, meta={"package": pkg})
            if ev:
                timeline.append(ev)

        self.log.info(f"  Installed apps: {len(records)}")
        return records, entities, timeline

    def _apps_dump(self, path: str):
        text = _read_text(path)
        if not text:
            return [], [], []
        records: List[ParsedRecord] = []
        entities: List[ExtractedEntity] = []
        for m in re.finditer(r"Package \[([^\]]+)\].*?firstInstallTime=(\S+).*?lastUpdateTime=(\S+)",
                              text, re.S):
            pkg, install_ts, update_ts = m.group(1), m.group(2), m.group(3)
            r = self._base_record(ArtifactType.ANDROID_APPS_DUMP, path)
            r.content = {"package": pkg, "first_install": install_ts,
                          "last_update": update_ts}
            records.append(r)
            entities.append(ExtractedEntity(
                artifact_id=r.record_id, device_id=self.device_id,
                case_id=self.case_id, entity_type=EntityType.PACKAGE,
                entity_value=pkg, source_file=path,
                artifact_type=ArtifactType.ANDROID_APPS_DUMP))
        return records, entities, []

    def _calendar(self, path: str):
        text = _read_text(path)
        if not text:
            return [], [], []
        records, entities, timeline = [], [], []

        for row in self._iter_rows(text):
            ts  = _unix_ms(row.get("dtstart", 0))
            r   = self._base_record(ArtifactType.ANDROID_CALENDAR, path)
            r.timestamp_utc = ts
            r.timestamp_raw = row.get("dtstart", "")
            r.event_type    = EventType.CALENDAR_EVENT
            r.content = {
                "title":    row.get("title", ""),
                "desc":     row.get("description", "")[:200],
                "location": row.get("eventLocation", ""),
                "dtstart":  ts,
                "dtend":    _unix_ms(row.get("dtend", 0)),
                "organizer":row.get("organizer", ""),
            }
            records.append(r)
            entities.extend(self.extractor.extract(
                row.get("title","")+" "+row.get("description",""),
                r.record_id, self.device_id, self.case_id,
                path, ArtifactType.ANDROID_CALENDAR, ts))
            ev = self._tl(r.record_id, ts, EventType.CALENDAR_EVENT,
                           f"Calendar: {r.content['title'][:80]}", path,
                           meta=r.content)
            if ev:
                timeline.append(ev)

        self.log.info(f"  Calendar: {len(records)} events")
        return records, entities, timeline

    def _mms(self, path: str):
        text = _read_text(path)
        if not text:
            return [], [], []
        records, entities, timeline = [], [], []
        for row in self._iter_rows(text):
            ts = _unix_ms(row.get("date", 0))
            r  = self._base_record(ArtifactType.ANDROID_MMS, path)
            r.timestamp_utc = ts
            r.timestamp_raw = row.get("date", "")
            r.event_type    = EventType.MMS_MESSAGE
            r.content = {"sub": row.get("sub", ""), "read": row.get("read", ""),
                          "m_type": row.get("m_type", "")}
            records.append(r)
            entities.extend(self._entities_from_row(row, r.record_id, path,
                                                      ArtifactType.ANDROID_MMS, ts))
        return records, entities, timeline

    def _downloads(self, path: str):
        text = _read_text(path)
        if not text:
            return [], [], []
        records, entities, timeline = [], [], []
        for row in self._iter_rows(text):
            ts  = _unix_ms(row.get("date", row.get("lastmodifiedtimestamp", 0)))
            r   = self._base_record(ArtifactType.ANDROID_DOWNLOADS, path)
            r.timestamp_utc = ts
            r.event_type    = EventType.DOWNLOAD
            r.content = {
                "title":     row.get("title", ""),
                "uri":       row.get("uri", ""),
                "local_uri": row.get("local_uri", row.get("_data", "")),
                "total_size":row.get("total_size", ""),
            }
            records.append(r)
            entities.extend(self.extractor.extract(
                row.get("uri","")+" "+row.get("title",""),
                r.record_id, self.device_id, self.case_id,
                path, ArtifactType.ANDROID_DOWNLOADS, ts))
            ev = self._tl(r.record_id, ts, EventType.DOWNLOAD,
                           f"Download: {r.content['title'] or r.content['uri']}"[:120],
                           path, meta=r.content)
            if ev:
                timeline.append(ev)
        return records, entities, timeline

    def _media(self, path: str):
        text = _read_text(path)
        if not text:
            return [], [], []
        records: List[ParsedRecord] = []
        for row in self._iter_rows(text):
            ts = _unix_s(row.get("date_added", 0))
            r  = self._base_record(ArtifactType.ANDROID_MEDIA, path)
            r.timestamp_utc = ts
            r.event_type    = EventType.MEDIA_EVENT
            r.content = {
                "name": row.get("_display_name", ""),
                "data": row.get("data", ""),
                "size": row.get("size", ""),
            }
            records.append(r)
        return records, [], []

    def _device_props(self, path: str):
        text = _read_text(path)
        if not text:
            return [], [], []
        props: Dict[str, str] = {}
        for line in text.splitlines():
            m = re.match(r'\[(.+?)\]:\s*\[(.+?)\]', line)
            if m:
                props[m.group(1)] = m.group(2)

        r = self._base_record(ArtifactType.ANDROID_DEVICE_PROPS, path)
        r.content = props
        entities  = self.extractor.extract(text, r.record_id, self.device_id,
                                            self.case_id, path,
                                            ArtifactType.ANDROID_DEVICE_PROPS)
        # Promote IMEI if present
        imei = props.get("persist.radio.imei", props.get("ro.telecom.imei",""))
        if imei and re.fullmatch(r"\d{15}", imei):
            entities.append(ExtractedEntity(
                artifact_id=r.record_id, device_id=self.device_id,
                case_id=self.case_id, entity_type=EntityType.IMEI,
                entity_value=imei, source_file=path,
                artifact_type=ArtifactType.ANDROID_DEVICE_PROPS))
        return [r], entities, []

    def _logcat(self, path: str):
        text = _read_text(path)
        if not text:
            return [], [], []
        r = self._base_record(ArtifactType.ANDROID_LOGCAT, path)
        r.content  = {"line_count": text.count("\n")}
        r.raw_text = text[:3000]
        entities   = self.extractor.extract(text, r.record_id, self.device_id,
                                             self.case_id, path,
                                             ArtifactType.ANDROID_LOGCAT)
        return [r], entities, []

    def _accounts(self, path: str):
        text = _read_text(path)
        if not text:
            return [], [], []
        r = self._base_record(ArtifactType.ANDROID_ACCOUNTS, path)
        accounts: List[str] = re.findall(r'Account \{name=([^,]+), type=([^}]+)\}', text)
        r.content  = {"accounts": [{"name": a[0], "type": a[1]} for a in accounts]}
        entities   = self.extractor.extract(text, r.record_id, self.device_id,
                                             self.case_id, path,
                                             ArtifactType.ANDROID_ACCOUNTS)
        return [r], entities, []

    def _wifi(self, path: str):
        text = _read_text(path)
        if not text:
            return [], [], []
        records: List[ParsedRecord] = []
        entities: List[ExtractedEntity] = []
        timeline: List[TimelineEvent]   = []
        ssid_pattern = re.compile(r'(?:SSID|ssid)\s*[=:]\s*"?([^"\n,<]+)"?', re.I)
        for m in ssid_pattern.finditer(text):
            ssid = m.group(1).strip()
            if not ssid or ssid in ("<unknown ssid>", ""):
                continue
            r = self._base_record(ArtifactType.ANDROID_WIFI, path)
            r.content = {"ssid": ssid}
            records.append(r)
            entities.append(ExtractedEntity(
                artifact_id=r.record_id, device_id=self.device_id,
                case_id=self.case_id, entity_type=EntityType.WIFI_SSID,
                entity_value=ssid, context=_snippet(text, m.start()),
                source_file=path, artifact_type=ArtifactType.ANDROID_WIFI))
            ev = self._tl(r.record_id, "", EventType.WIFI_JOIN,
                           f"Known WiFi network: {ssid}", path, meta={"ssid": ssid})
            if ev:
                timeline.append(ev)
        return records, entities, timeline

    def _network(self, path: str):
        text = _read_text(path)
        if not text:
            return [], [], []
        r = self._base_record(ArtifactType.ANDROID_NETWORK, path)
        r.raw_text = text[:2000]
        entities   = self.extractor.extract(text, r.record_id, self.device_id,
                                             self.case_id, path,
                                             ArtifactType.ANDROID_NETWORK)
        return [r], entities, []

    def _processes(self, path: str):
        text = _read_text(path)
        if not text:
            return [], [], []
        records: List[ParsedRecord] = []
        for line in text.splitlines()[1:]:   # skip header
            parts = line.split()
            if len(parts) < 8:
                continue
            r = self._base_record(ArtifactType.ANDROID_PROCESSES, path)
            r.content = {"user": parts[0], "pid": parts[1],
                          "name": parts[-1] if parts else ""}
            records.append(r)
        return records, [], []


# ─────────────────────────────────────────────────────────────────────────────
# Windows Parser
# ─────────────────────────────────────────────────────────────────────────────

class WindowsParser(BasePlatformParser):
    """Parses Windows offline artifacts produced by WindowsCollector."""

    PLATFORM = "windows"

    def parse(self, file_path: str, artifact_type: str):
        dispatch = {
            ArtifactType.WIN_REGISTRY:       self._registry,
            ArtifactType.WIN_EVTX:           self._evtx,
            ArtifactType.WIN_PREFETCH:       self._prefetch,
            ArtifactType.WIN_BROWSER_CHROME: self._browser_sqlite,
            ArtifactType.WIN_BROWSER_EDGE:   self._browser_sqlite,
            ArtifactType.WIN_BROWSER_FIREFOX:self._firefox_sqlite,
            ArtifactType.WIN_USER_ACCOUNTS:  self._user_accounts,
            ArtifactType.WIN_FILE_LISTING:   self._file_listing,
            ArtifactType.WIN_SYSTEM_INFO:    self._system_info,
            ArtifactType.WIN_SPECIAL_FILES:  self._special_files,
            ArtifactType.WIN_USB:            self._usb_log,
            ArtifactType.WIN_SCHEDULED_TASKS:self._scheduled_tasks,
        }
        fn = dispatch.get(artifact_type)
        if fn is None:
            return [], [], []
        try:
            return fn(file_path)
        except Exception as exc:
            self.log.error(f"Windows parse error [{artifact_type}] {file_path}: {exc}")
            return [], [], []

    def _registry(self, path: str):
        """Record hive location; parse content if python-registry is available."""
        fname = os.path.basename(path)
        r = self._base_record(ArtifactType.WIN_REGISTRY, path)
        r.content = {
            "hive_name": fname,
            "size_bytes": os.path.getsize(path) if os.path.exists(path) else 0,
            "parsed":     False,
        }
        entities: List[ExtractedEntity] = []

        if HAS_REGISTRY:
            try:
                reg  = _reg_lib.Registry(path)
                keys = self._walk_registry(reg.root())
                r.content["key_count"] = len(keys)
                r.content["parsed"]    = True
                r.content["keys"]      = keys[:200]   # cap for storage
                text = " ".join(str(k) for k in keys)
                entities = self.extractor.extract(text, r.record_id,
                                                   self.device_id, self.case_id,
                                                   path, ArtifactType.WIN_REGISTRY)
            except Exception as exc:
                r.content["parse_error"] = str(exc)
        else:
            r.content["note"] = "Install python-registry for full hive parsing"

        return [r], entities, []

    def _walk_registry(self, key, depth: int = 0, max_depth: int = 4) -> List[str]:
        results = [key.path()]
        if depth >= max_depth:
            return results
        try:
            for subkey in key.subkeys():
                results.extend(self._walk_registry(subkey, depth + 1, max_depth))
        except Exception:
            pass
        return results

    def _evtx(self, path: str):
        """Parse Windows EVTX event logs; requires python-evtx."""
        records: List[ParsedRecord] = []
        entities: List[ExtractedEntity] = []
        timeline: List[TimelineEvent]   = []

        if not HAS_EVTX:
            r = self._base_record(ArtifactType.WIN_EVTX, path)
            r.content = {"file": os.path.basename(path),
                          "note": "Install python-evtx for EVTX parsing"}
            return [r], [], []

        # Key event IDs and their timeline mapping
        EVTX_EVENTS = {
            "4624": (EventType.USER_LOGON,    "Successful logon"),
            "4625": (EventType.LOGIN_FAILED,  "Failed logon"),
            "4634": (EventType.USER_LOGOFF,   "Logoff"),
            "4648": (EventType.USER_LOGON,    "Logon with explicit credentials"),
            "4688": (EventType.PROCESS_CREATED,"Process created"),
            "4698": (EventType.SERVICE_EVENT, "Scheduled task created"),
            "4720": (EventType.ACCOUNT_EVENT, "User account created"),
            "4726": (EventType.ACCOUNT_EVENT, "User account deleted"),
            "7034": (EventType.SERVICE_EVENT, "Service crashed"),
            "7036": (EventType.SERVICE_EVENT, "Service state change"),
        }
        try:
            with _evtx_lib.Evtx(path) as log:
                for evtx_record in log.records():
                    try:
                        xml_str = evtx_record.xml()
                        root    = _ET.fromstring(xml_str)
                        ns      = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

                        event_id = root.findtext("e:System/e:EventID", "", ns)
                        ts_raw   = root.findtext("e:System/e:TimeCreated", "", ns)
                        if not ts_raw:
                            attr = root.find("e:System/e:TimeCreated", ns)
                            ts_raw = attr.get("SystemTime", "") if attr is not None else ""
                        computer = root.findtext("e:System/e:Computer", "", ns)
                        channel  = root.findtext("e:System/e:Channel", "", ns)

                        ts_utc = _iso_ts(ts_raw)

                        r = self._base_record(ArtifactType.WIN_EVTX, path)
                        r.timestamp_utc = ts_utc
                        r.timestamp_raw = ts_raw
                        r.event_type    = EVTX_EVENTS.get(event_id, ("",""))[0]
                        r.content       = {
                            "event_id": event_id,
                            "computer": computer,
                            "channel":  channel,
                            "xml_hash": hashlib.md5(xml_str.encode()).hexdigest(),
                        }

                        # Extract EventData fields
                        for data in root.findall(".//e:Data", ns):
                            name = data.get("Name", "")
                            if name and data.text:
                                r.content[name] = data.text

                        records.append(r)

                        # Entity extraction from full XML
                        ents = self.extractor.extract(xml_str, r.record_id,
                                                       self.device_id, self.case_id,
                                                       path, ArtifactType.WIN_EVTX, ts_utc)
                        entities.extend(ents)

                        # Timeline for key events
                        if event_id in EVTX_EVENTS and ts_utc:
                            etype, desc_tmpl = EVTX_EVENTS[event_id]
                            actor   = r.content.get("SubjectUserName", "")
                            target  = r.content.get("TargetUserName",
                                       r.content.get("NewProcessName", ""))
                            ev = self._tl(r.record_id, ts_utc, etype,
                                           f"{desc_tmpl} [{event_id}] on {computer}",
                                           path, actor=actor, target=target,
                                           meta={"event_id": event_id,
                                                  "channel": channel})
                            if ev:
                                timeline.append(ev)

                    except Exception:
                        pass

        except Exception as exc:
            self.log.warning(f"EVTX read error {path}: {exc}")

        fname = os.path.basename(path)
        self.log.info(f"  EVTX [{fname}]: {len(records)} events")
        return records, entities, timeline

    def _prefetch(self, path: str):
        """Extract executable name and run-count hint from .pf filename."""
        fname = os.path.basename(path)
        # Format: EXECUTABLE.EXE-HASHVALUE.pf
        m = re.match(r"(.+?)-([0-9A-F]{8})\.pf", fname, re.I)
        exe = m.group(1) if m else fname
        r   = self._base_record(ArtifactType.WIN_PREFETCH, path)
        r.content = {"executable": exe, "filename": fname,
                      "size_bytes": os.path.getsize(path) if os.path.exists(path) else 0}
        r.event_type = EventType.PROCESS_CREATED
        ev = self._tl(r.record_id, "", EventType.PROCESS_CREATED,
                       f"Prefetch: {exe} executed", path, meta=r.content)
        tl = [ev] if ev else []
        return [r], [], tl

    def _browser_sqlite(self, path: str):
        """Parse Chrome or Edge History SQLite database."""
        records: List[ParsedRecord] = []
        entities: List[ExtractedEntity] = []
        timeline: List[TimelineEvent]   = []

        # Chrome / Edge History DB schema:
        # urls(id, url, title, visit_count, last_visit_time)
        try:
            conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
            cur  = conn.cursor()
            cur.execute("SELECT url, title, visit_count, last_visit_time FROM urls "
                         "ORDER BY last_visit_time DESC")
            for url, title, visits, chrome_ts in cur.fetchall():
                ts  = _chrome_ts(chrome_ts)
                r   = self._base_record(ArtifactType.WIN_BROWSER_CHROME, path)
                r.timestamp_utc = ts
                r.timestamp_raw = str(chrome_ts)
                r.event_type    = EventType.BROWSER_VISIT
                r.content = {"url": url, "title": title, "visit_count": visits}
                records.append(r)
                ents = self.extractor.extract(f"{url} {title}", r.record_id,
                                               self.device_id, self.case_id,
                                               path, ArtifactType.WIN_BROWSER_CHROME, ts)
                entities.extend(ents)
                ev = self._tl(r.record_id, ts, EventType.BROWSER_VISIT,
                               f"Visited: {title or url}"[:150], path,
                               target=url, meta={"visits": visits})
                if ev:
                    timeline.append(ev)
            conn.close()
        except sqlite3.OperationalError as exc:
            self.log.debug(f"Browser SQLite error {path}: {exc}")
        except Exception as exc:
            self.log.warning(f"Browser parse error {path}: {exc}")

        self.log.info(f"  Browser history [{os.path.basename(path)}]: {len(records)}")
        return records, entities, timeline

    def _firefox_sqlite(self, path: str):
        """Parse Firefox places.sqlite."""
        records: List[ParsedRecord] = []
        entities: List[ExtractedEntity] = []
        timeline: List[TimelineEvent]   = []
        try:
            conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
            cur  = conn.cursor()
            cur.execute("SELECT url, title, visit_count, last_visit_date "
                         "FROM moz_places ORDER BY last_visit_date DESC")
            for url, title, visits, ff_ts in cur.fetchall():
                ts  = _firefox_ts(ff_ts) if ff_ts else ""
                r   = self._base_record(ArtifactType.WIN_BROWSER_FIREFOX, path)
                r.timestamp_utc = ts
                r.event_type    = EventType.BROWSER_VISIT
                r.content = {"url": url, "title": title or "", "visit_count": visits}
                records.append(r)
                ents = self.extractor.extract(f"{url} {title or ''}", r.record_id,
                                               self.device_id, self.case_id,
                                               path, ArtifactType.WIN_BROWSER_FIREFOX, ts)
                entities.extend(ents)
                ev = self._tl(r.record_id, ts, EventType.BROWSER_VISIT,
                               f"Firefox: {title or url}"[:150], path,
                               target=url, meta={"visits": visits})
                if ev:
                    timeline.append(ev)
            conn.close()
        except Exception as exc:
            self.log.debug(f"Firefox SQLite error {path}: {exc}")

        return records, entities, timeline

    def _user_accounts(self, path: str):
        data = _read_json(path)
        if not data:
            return [], [], []
        records: List[ParsedRecord] = []
        entities: List[ExtractedEntity] = []
        for acct in (data if isinstance(data, list) else [data]):
            r = self._base_record(ArtifactType.WIN_USER_ACCOUNTS, path)
            r.content = acct
            records.append(r)
            username = acct.get("username", "")
            if username and username not in ("Public","Default","All Users"):
                entities.append(ExtractedEntity(
                    artifact_id=r.record_id, device_id=self.device_id,
                    case_id=self.case_id, entity_type=EntityType.USERNAME,
                    entity_value=username, source_file=path,
                    artifact_type=ArtifactType.WIN_USER_ACCOUNTS))
        return records, entities, []

    def _file_listing(self, path: str):
        """Parse TSV file listing: mtime\tsize\tpath"""
        text = _read_text(path)
        if not text:
            return [], [], []
        records: List[ParsedRecord] = []
        for line in text.splitlines()[1:]:     # skip header
            parts = line.split("\t", 2)
            if len(parts) < 3:
                continue
            mtime, size, fpath = parts
            ts = _unix_s(mtime)
            r  = self._base_record(ArtifactType.WIN_FILE_LISTING, path)
            r.timestamp_utc = ts
            r.content = {"path": fpath, "size_bytes": size, "mtime": ts}
            records.append(r)
        self.log.info(f"  File listing: {len(records)} entries")
        return records, [], []

    def _system_info(self, path: str):
        data = _read_json(path) or {}
        r    = self._base_record(ArtifactType.WIN_SYSTEM_INFO, path)
        r.content = data
        return [r], [], []

    def _special_files(self, path: str):
        data = _read_json(path) or {}
        r    = self._base_record(ArtifactType.WIN_SPECIAL_FILES, path)
        r.content = data
        return [r], [], []

    def _usb_log(self, path: str):
        text = _read_text(path)
        if not text:
            return [], [], []
        records: List[ParsedRecord] = []
        timeline: List[TimelineEvent]   = []
        # SetupAPI dev log: look for "Device Install" lines
        for m in re.finditer(
                r'\[(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d+)\]\s+Device Install.*?VID_([0-9A-F]{4})&PID_([0-9A-F]{4})',
                text, re.I):
            ts_raw, vid, pid = m.group(1), m.group(2), m.group(3)
            ts = _iso_ts(ts_raw)
            r  = self._base_record(ArtifactType.WIN_USB, path)
            r.timestamp_utc = ts
            r.content = {"vid": vid, "pid": pid, "raw_ts": ts_raw}
            r.event_type = EventType.USB_CONNECTED
            records.append(r)
            ev = self._tl(r.record_id, ts, EventType.USB_CONNECTED,
                           f"USB device connected VID:{vid} PID:{pid}", path,
                           meta=r.content)
            if ev:
                timeline.append(ev)
        return records, [], timeline

    def _scheduled_tasks(self, path: str):
        text = _read_text(path)
        if not text:
            return [], [], []
        r = self._base_record(ArtifactType.WIN_SCHEDULED_TASKS, path)
        r.content = {"filename": os.path.basename(path), "raw": text[:2000]}
        # Extract command/action from XML
        for tag in ("Command", "Arguments", "URI"):
            m = re.search(rf"<{tag}>(.*?)</{tag}>", text, re.S | re.I)
            if m:
                r.content[tag.lower()] = m.group(1).strip()
        entities = self.extractor.extract(text, r.record_id, self.device_id,
                                           self.case_id, path,
                                           ArtifactType.WIN_SCHEDULED_TASKS)
        return [r], entities, []


# ─────────────────────────────────────────────────────────────────────────────
# Linux Parser
# ─────────────────────────────────────────────────────────────────────────────

class LinuxParser(BasePlatformParser):
    """Parses Linux artifacts produced by LinuxCollector."""

    PLATFORM = "linux"

    def parse(self, file_path: str, artifact_type: str):
        dispatch = {
            ArtifactType.LINUX_PASSWD:       self._passwd,
            ArtifactType.LINUX_SHADOW:       self._shadow,
            ArtifactType.LINUX_GROUP:        self._group,
            ArtifactType.LINUX_SUDOERS:      self._sudoers,
            ArtifactType.LINUX_AUTH_LOG:     self._auth_log,
            ArtifactType.LINUX_SYSLOG:       self._syslog,
            ArtifactType.LINUX_SHELL_HISTORY:self._shell_history,
            ArtifactType.LINUX_SSH_ARTIFACT: self._ssh_artifact,
            ArtifactType.LINUX_SSH_KEY:      self._ssh_key,
            ArtifactType.LINUX_CRON:         self._cron,
            ArtifactType.LINUX_SYSTEMD:      self._systemd,
            ArtifactType.LINUX_NETWORK:      self._network,
            ArtifactType.LINUX_PACKAGES:     self._packages,
            ArtifactType.LINUX_PROCESSES:    self._processes,
            ArtifactType.ACCOUNTS_SUMMARY:   self._accounts_summary,
        }
        fn = dispatch.get(artifact_type)
        if fn is None:
            return [], [], []
        try:
            return fn(file_path)
        except Exception as exc:
            self.log.error(f"Linux parse error [{artifact_type}] {file_path}: {exc}")
            return [], [], []

    def _passwd(self, path: str):
        text = _read_text(path)
        if not text:
            return [], [], []
        records, entities = [], []
        for line in text.splitlines():
            parts = line.split(":")
            if len(parts) < 7:
                continue
            uid = int(parts[2]) if parts[2].isdigit() else -1
            r   = self._base_record(ArtifactType.LINUX_PASSWD, path)
            r.content = {
                "username": parts[0], "uid": uid,
                "gid":      parts[3], "gecos": parts[4],
                "home":     parts[5], "shell": parts[6].strip(),
            }
            records.append(r)
            if parts[0]:
                entities.append(ExtractedEntity(
                    artifact_id=r.record_id, device_id=self.device_id,
                    case_id=self.case_id, entity_type=EntityType.USERNAME,
                    entity_value=parts[0], context=line,
                    source_file=path, artifact_type=ArtifactType.LINUX_PASSWD))
        self.log.info(f"  Passwd: {len(records)} accounts")
        return records, entities, []

    def _shadow(self, path: str):
        text = _read_text(path)
        if not text:
            return [], [], []
        records: List[ParsedRecord] = []
        for line in text.splitlines():
            parts = line.split(":")
            if len(parts) < 2:
                continue
            r = self._base_record(ArtifactType.LINUX_SHADOW, path)
            r.content = {
                "username":        parts[0],
                "hash_present":    len(parts[1]) > 2,
                "hash_type":       parts[1][:3] if parts[1].startswith("$") else "none",
                "last_change_days":parts[2] if len(parts) > 2 else "",
            }
            records.append(r)
        return records, [], []

    def _group(self, path: str):
        text = _read_text(path)
        if not text:
            return [], [], []
        records: List[ParsedRecord] = []
        for line in text.splitlines():
            parts = line.split(":")
            if len(parts) < 3:
                continue
            members = parts[3].strip().split(",") if len(parts) > 3 else []
            r = self._base_record(ArtifactType.LINUX_GROUP, path)
            r.content = {"group": parts[0], "gid": parts[2], "members": members}
            records.append(r)
        return records, [], []

    def _sudoers(self, path: str):
        text = _read_text(path)
        if not text:
            return [], [], []
        r = self._base_record(ArtifactType.LINUX_SUDOERS, path)
        rules = [l for l in text.splitlines()
                  if l.strip() and not l.startswith("#")]
        r.content  = {"rules": rules[:100]}
        r.raw_text = text[:3000]
        entities   = self.extractor.extract(text, r.record_id, self.device_id,
                                             self.case_id, path,
                                             ArtifactType.LINUX_SUDOERS)
        return [r], entities, []

    def _auth_log(self, path: str):
        text = _read_text(path)
        if not text:
            return [], [], []
        records: List[ParsedRecord] = []
        entities: List[ExtractedEntity] = []
        timeline: List[TimelineEvent]   = []
        year = datetime.datetime.utcnow().year

        for line in text.splitlines():
            r    = None
            ts   = ""
            ents: List[ExtractedEntity] = []

            # SSH successful login
            m = _RE_SSH_OK.search(line)
            if m:
                ts   = _syslog_ts(m.group(1), year)
                user = m.group(4)
                src  = m.group(5)
                port = m.group(6)
                r    = self._base_record(ArtifactType.LINUX_AUTH_LOG, path)
                r.timestamp_utc = ts; r.event_type = EventType.LOGIN_SUCCESS
                r.content = {"user": user, "src_ip": src, "port": port,
                              "method": m.group(3), "host": m.group(2)}
                ev = self._tl(r.record_id, ts, EventType.LOGIN_SUCCESS,
                               f"SSH login: {user} from {src}", path,
                               actor=src, target=user,
                               meta={"port": port, "method": m.group(3)})
                if ev:
                    timeline.append(ev)
                ents = [ExtractedEntity(
                    artifact_id=r.record_id, device_id=self.device_id,
                    case_id=self.case_id, entity_type=EntityType.IPV4,
                    entity_value=src, context=line[:SNIPPET_WIDTH],
                    source_file=path, artifact_type=ArtifactType.LINUX_AUTH_LOG,
                    first_seen=ts)]
                if r:
                    records.append(r)
                    entities.extend(ents)
                continue

            # SSH failed
            m = _RE_SSH_FAIL.search(line)
            if m:
                ts   = _syslog_ts(m.group(1), year)
                user = m.group(3)
                src  = m.group(4)
                r    = self._base_record(ArtifactType.LINUX_AUTH_LOG, path)
                r.timestamp_utc = ts; r.event_type = EventType.LOGIN_FAILED
                r.content = {"user": user, "src_ip": src, "host": m.group(2)}
                ev = self._tl(r.record_id, ts, EventType.LOGIN_FAILED,
                               f"SSH fail: {user} from {src}", path,
                               actor=src, target=user)
                if ev:
                    timeline.append(ev)
                if r:
                    records.append(r)
                    entities.append(ExtractedEntity(
                        artifact_id=r.record_id, device_id=self.device_id,
                        case_id=self.case_id, entity_type=EntityType.IPV4,
                        entity_value=src, context=line[:SNIPPET_WIDTH],
                        source_file=path, artifact_type=ArtifactType.LINUX_AUTH_LOG,
                        first_seen=ts))
                continue

            # SSH invalid user
            m = _RE_SSH_INVAL.search(line)
            if m:
                ts   = _syslog_ts(m.group(1), year)
                r    = self._base_record(ArtifactType.LINUX_AUTH_LOG, path)
                r.timestamp_utc = ts; r.event_type = EventType.LOGIN_FAILED
                r.content = {"user": m.group(3), "src_ip": m.group(4),
                              "reason": "invalid_user"}
                if r:
                    records.append(r)
                continue

            # sudo command
            m = _RE_SUDO.search(line)
            if m:
                ts   = _syslog_ts(m.group(1), year)
                user = m.group(3)
                cmd  = m.group(4).strip()
                r    = self._base_record(ArtifactType.LINUX_AUTH_LOG, path)
                r.timestamp_utc = ts; r.event_type = EventType.SUDO_CMD
                r.content = {"user": user, "command": cmd, "host": m.group(2)}
                ev = self._tl(r.record_id, ts, EventType.SUDO_CMD,
                               f"sudo: {user} ran: {cmd[:80]}", path,
                               actor=user, target="root", meta={"cmd": cmd})
                if ev:
                    timeline.append(ev)
                if r:
                    records.append(r)
                    entities.extend(self.extractor.extract(
                        cmd, r.record_id, self.device_id, self.case_id,
                        path, ArtifactType.LINUX_AUTH_LOG, ts))
                continue

            # PAM session
            m = _RE_SESSION.search(line)
            if m:
                ts  = _syslog_ts(m.group(1), year)
                act = m.group(3)   # opened / closed
                usr = m.group(4)
                etype = EventType.USER_LOGON if act == "opened" else EventType.USER_LOGOFF
                r   = self._base_record(ArtifactType.LINUX_AUTH_LOG, path)
                r.timestamp_utc = ts; r.event_type = etype
                r.content = {"user": usr, "session": act, "host": m.group(2)}
                ev = self._tl(r.record_id, ts, etype,
                               f"Session {act} for {usr}", path,
                               actor=usr, meta={"action": act})
                if ev:
                    timeline.append(ev)
                if r:
                    records.append(r)

        self.log.info(f"  Auth log: {len(records)} events, {len(timeline)} timeline")
        return records, entities, timeline

    def _syslog(self, path: str):
        text = _read_text(path)
        if not text:
            return [], [], []
        r = self._base_record(ArtifactType.LINUX_SYSLOG, path)
        r.content  = {"line_count": text.count("\n"),
                       "source":    os.path.basename(path)}
        r.raw_text = text[:5000]
        entities   = self.extractor.extract(text, r.record_id, self.device_id,
                                             self.case_id, path,
                                             ArtifactType.LINUX_SYSLOG)
        return [r], entities, []

    def _shell_history(self, path: str):
        text = _read_text(path)
        if not text:
            return [], [], []
        records: List[ParsedRecord] = []
        entities: List[ExtractedEntity] = []
        timeline: List[TimelineEvent]   = []

        # Detect username from path (e.g. shell_history/alice/.bash_history)
        parts = Path(path).parts
        username = ""
        for i, p in enumerate(parts):
            if p == "shell_history" and i + 1 < len(parts):
                username = parts[i + 1]
                break

        ts_re = re.compile(r"^#(\d{10})$")
        current_ts = ""

        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            # History files may embed timestamps as "#UNIX_TS"
            m = ts_re.match(line)
            if m:
                current_ts = _unix_s(m.group(1))
                continue
            r = self._base_record(ArtifactType.LINUX_SHELL_HISTORY, path)
            r.timestamp_utc = current_ts
            r.event_type    = EventType.SHELL_CMD
            r.content       = {"command": line, "user": username}
            r.raw_text      = line
            records.append(r)

            # Entity extraction from commands
            ents = self.extractor.extract(line, r.record_id, self.device_id,
                                           self.case_id, path,
                                           ArtifactType.LINUX_SHELL_HISTORY,
                                           current_ts)
            entities.extend(ents)

            ev = self._tl(r.record_id, current_ts, EventType.SHELL_CMD,
                           f"[{username}]$ {line[:120]}", path,
                           actor=username, meta={"command": line})
            if ev:
                timeline.append(ev)

        self.log.info(f"  Shell history [{username}]: {len(records)} commands")
        return records, entities, timeline

    def _ssh_artifact(self, path: str):
        text = _read_text(path)
        if not text:
            return [], [], []
        r = self._base_record(ArtifactType.LINUX_SSH_ARTIFACT, path)
        r.content  = {"filename": os.path.basename(path), "preview": text[:200]}
        entities   = self.extractor.extract(text, r.record_id, self.device_id,
                                             self.case_id, path,
                                             ArtifactType.LINUX_SSH_ARTIFACT)
        return [r], entities, []

    def _ssh_key(self, path: str):
        text = _read_text(path)
        if not text:
            return [], [], []
        r = self._base_record(ArtifactType.LINUX_SSH_KEY, path)
        key_type = "unknown"
        if "RSA" in text:       key_type = "RSA"
        elif "OPENSSH" in text: key_type = "OpenSSH"
        elif "EC" in text:      key_type = "ECDSA"
        r.content = {
            "filename": os.path.basename(path),
            "key_type": key_type,
            "note":     "Private key — handle with care",
        }
        return [r], [], []

    def _cron(self, path: str):
        text = _read_text(path)
        if not text:
            return [], [], []
        records: List[ParsedRecord] = []
        entities: List[ExtractedEntity] = []
        timeline: List[TimelineEvent]   = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Cron line: MIN HOUR DOM MON DOW COMMAND
            m = re.match(r"((?:[\d\*/\-,]+\s+){5})(.+)", line)
            if m:
                schedule = m.group(1).strip()
                command  = m.group(2).strip()
                r = self._base_record(ArtifactType.LINUX_CRON, path)
                r.event_type = EventType.CRON_JOB
                r.content    = {"schedule": schedule, "command": command,
                                 "source_file": os.path.basename(path)}
                records.append(r)
                ents = self.extractor.extract(command, r.record_id,
                                               self.device_id, self.case_id,
                                               path, ArtifactType.LINUX_CRON)
                entities.extend(ents)
                ev = self._tl(r.record_id, "", EventType.CRON_JOB,
                               f"Cron [{schedule}]: {command[:80]}", path,
                               meta=r.content)
                if ev:
                    timeline.append(ev)
        return records, entities, timeline

    def _systemd(self, path: str):
        text = _read_text(path)
        if not text:
            return [], [], []
        r = self._base_record(ArtifactType.LINUX_SYSTEMD, path)
        unit_name = os.path.basename(path)
        r.content = {"unit": unit_name}
        for key in ("ExecStart", "ExecStartPre", "User", "Group",
                     "WorkingDirectory", "After", "WantedBy", "Type"):
            m = re.search(rf"^{key}\s*=\s*(.+)$", text, re.M)
            if m:
                r.content[key.lower()] = m.group(1).strip()
        r.event_type = EventType.SYSTEMD_UNIT if "SERVICE" in unit_name.upper() else ""
        entities = self.extractor.extract(text, r.record_id, self.device_id,
                                           self.case_id, path,
                                           ArtifactType.LINUX_SYSTEMD)
        return [r], entities, []

    def _network(self, path: str):
        text = _read_text(path)
        if not text:
            return [], [], []
        r = self._base_record(ArtifactType.LINUX_NETWORK, path)
        r.content  = {"source": os.path.basename(path)}
        r.raw_text = text[:3000]
        entities   = self.extractor.extract(text, r.record_id, self.device_id,
                                             self.case_id, path,
                                             ArtifactType.LINUX_NETWORK)
        return [r], entities, []

    def _packages(self, path: str):
        text = _read_text(path)
        if not text:
            return [], [], []
        records: List[ParsedRecord] = []
        src = os.path.basename(path)
        is_dpkg = "dpkg" in src
        is_rpm  = "rpm" in src

        for line in text.splitlines()[1:]:    # skip header
            line = line.strip()
            if not line or line.startswith("ii") is False and is_dpkg:
                pass
            if is_dpkg:
                parts = line.split()
                if len(parts) >= 3 and parts[0] in ("ii","hi","rc","pn"):
                    r = self._base_record(ArtifactType.LINUX_PACKAGES, path)
                    r.content = {"name": parts[1], "version": parts[2],
                                  "status": parts[0]}
                    records.append(r)
            elif is_rpm:
                parts = line.split("|")
                if len(parts) >= 3:
                    r = self._base_record(ArtifactType.LINUX_PACKAGES, path)
                    r.content = {"name": parts[0].strip(),
                                  "version": parts[1].strip(),
                                  "install_date": parts[2].strip()}
                    records.append(r)
            else:
                r = self._base_record(ArtifactType.LINUX_PACKAGES, path)
                r.content = {"raw": line}
                records.append(r)
        self.log.info(f"  Packages [{src}]: {len(records)}")
        return records, [], []

    def _processes(self, path: str):
        text = _read_text(path)
        if not text:
            return [], [], []
        records: List[ParsedRecord] = []
        for line in text.splitlines()[1:]:
            parts = line.split(None, 10)
            if len(parts) < 10:
                continue
            r = self._base_record(ArtifactType.LINUX_PROCESSES, path)
            r.event_type = EventType.PROCESS_CREATED
            r.content = {
                "user": parts[0], "pid": parts[1],
                "cpu":  parts[2], "mem": parts[3],
                "cmd":  parts[-1],
            }
            records.append(r)
        return records, [], []

    def _accounts_summary(self, path: str):
        data = _read_json(path)
        if not data:
            return [], [], []
        records: List[ParsedRecord] = []
        entities: List[ExtractedEntity] = []
        for acct in (data if isinstance(data, list) else [data]):
            r = self._base_record(ArtifactType.ACCOUNTS_SUMMARY, path)
            r.content = acct
            records.append(r)
            un = acct.get("user", acct.get("username", ""))
            if un:
                entities.append(ExtractedEntity(
                    artifact_id=r.record_id, device_id=self.device_id,
                    case_id=self.case_id, entity_type=EntityType.USERNAME,
                    entity_value=un, source_file=path,
                    artifact_type=ArtifactType.ACCOUNTS_SUMMARY))
        return records, entities, []


# ─────────────────────────────────────────────────────────────────────────────
# Universal HIVE Parser — Orchestrator
# ─────────────────────────────────────────────────────────────────────────────

class HIVEParser:
    """
    Orchestrates the full parsing pipeline for one or more cases / devices.

    Workflow per device directory:
      1. Read MANIFEST.json → register device in EvidenceDatabase
      2. Recursively walk artifact directories
      3. Detect artifact type for each file
      4. Dispatch to the correct platform parser
      5. Bulk-insert records, entities, and timeline events
      6. Log errors without stopping
    """

    PARSER_MAP: Dict[str, type] = {
        "android": AndroidParser,
        "windows": WindowsParser,
        "linux":   LinuxParser,
    }

    def __init__(self, db: EvidenceDatabase, workers: int = DEFAULT_WORKERS):
        self.db        = db
        self.workers   = workers
        self.detector  = ArtifactDetector()
        self.extractor = EntityExtractor()
        self.log       = logging.getLogger("hive.parser.orchestrator")
        self._lock     = threading.Lock()
        self._result   = ParserResult()

    # ── Public entry points ───────────────────────────────────

    def parse_case(self, case_dir: str, case_id: str) -> ParserResult:
        """Parse all device subdirectories in a case directory."""
        self._result.case_id    = case_id
        self._result.db_path    = self.db.db_path
        self._result.started_at = _utcnow()
        self.log.info(f"{'═'*60}")
        self.log.info(f"[PARSER] Case: {case_id}  →  {case_dir}")

        device_dirs = self._find_device_dirs(case_dir)
        self.log.info(f"[PARSER] Found {len(device_dirs)} device director(ies)")

        with concurrent.futures.ThreadPoolExecutor(
                max_workers=self.workers,
                thread_name_prefix="hive_parse") as ex:
            futures = {ex.submit(self._parse_device_safe, d, case_id): d
                       for d in device_dirs}
            for fut in concurrent.futures.as_completed(futures):
                d = futures[fut]
                try:
                    fut.result()
                except Exception as exc:
                    self.log.error(f"Device parse failed [{d}]: {exc}")
                    with self._lock:
                        self._result.errors.append(f"{d}: {exc}")

        self._result.completed_at = _utcnow()
        stats = self.db.stats()
        self._result.records_parsed = stats.get("artifacts", 0)
        self._result.entities_found = stats.get("entities", 0)
        self._result.timeline_events= stats.get("timeline", 0)

        self._save_report(case_dir)
        self.log.info(f"[PARSER] Complete  artifacts={self._result.records_parsed}  "
                       f"entities={self._result.entities_found}  "
                       f"timeline={self._result.timeline_events}")
        return self._result

    def parse_single_device(self, device_dir: str, case_id: str) -> ParserResult:
        """Parse a single device directory."""
        self._result.case_id    = case_id
        self._result.db_path    = self.db.db_path
        self._result.started_at = _utcnow()
        self._parse_device_safe(device_dir, case_id)
        self._result.completed_at = _utcnow()
        stats = self.db.stats()
        self._result.records_parsed = stats.get("artifacts", 0)
        self._result.entities_found = stats.get("entities", 0)
        self._result.timeline_events= stats.get("timeline", 0)
        return self._result

    # ── Device-level parsing ──────────────────────────────────

    def _find_device_dirs(self, case_dir: str) -> List[str]:
        dirs = []
        for entry in os.scandir(case_dir):
            if entry.is_dir() and os.path.exists(
                    os.path.join(entry.path, "MANIFEST.json")):
                dirs.append(entry.path)
        return dirs

    def _parse_device_safe(self, device_dir: str, case_id: str) -> None:
        try:
            self._parse_device(device_dir, case_id)
        except Exception as exc:
            self.log.error(f"Device parse error [{device_dir}]: {exc}", exc_info=True)
            with self._lock:
                self._result.errors.append(f"{device_dir}: {exc}")

    def _parse_device(self, device_dir: str, case_id: str) -> None:
        manifest_path = os.path.join(device_dir, "MANIFEST.json")
        manifest      = _read_json(manifest_path) or {}

        device_id   = manifest.get("device_id", os.path.basename(device_dir))
        platform    = manifest.get("device_type", "unknown").lower()
        acq_id      = manifest.get("acquisition_id", "")

        self.db.upsert_device({**manifest, "case_id": case_id,
                                 "device_id": device_id})
        with self._lock:
            self._result.devices_parsed += 1

        self.log.info(f"  → Device: {device_id}  [{platform}]")

        parser_cls = self.PARSER_MAP.get(platform)
        if parser_cls is None:
            self.log.warning(f"    No parser for platform '{platform}'")
            parser_cls = self.PARSER_MAP.get("linux", LinuxParser)   # best guess

        platform_parser = parser_cls(device_id, case_id, acq_id, self.extractor)

        # Walk all artifact files
        artifacts_root = os.path.join(device_dir, "artifacts")
        if not os.path.isdir(artifacts_root):
            # Fallback: scan entire device dir
            artifacts_root = device_dir

        for root, _dirs, files in os.walk(artifacts_root):
            for fname in files:
                if fname == "MANIFEST.json":
                    continue
                fpath = os.path.join(root, fname)
                self._parse_file(fpath, platform_parser, device_id,
                                  case_id, platform)

    def _parse_file(self, file_path: str, parser: BasePlatformParser,
                     device_id: str, case_id: str, platform: str) -> None:
        atype = self.detector.detect(file_path)

        # For manifests and unknown files: entity-extract only
        if atype in (ArtifactType.MANIFEST, ArtifactType.UNKNOWN):
            if atype == ArtifactType.UNKNOWN:
                text = _read_text(file_path)
                if text:
                    r = ParsedRecord(
                        case_id=case_id, device_id=device_id,
                        platform=platform, artifact_type=ArtifactType.UNKNOWN,
                        source_file=file_path)
                    ents = self.extractor.extract(text, r.record_id, device_id,
                                                   case_id, file_path, atype)
                    if ents:
                        self.db.insert_artifact(r)
                        self.db.insert_entities_bulk(ents)
            return

        try:
            records, entities, timeline = parser.parse(file_path, atype)
        except Exception as exc:
            self.log.error(f"    Parse error [{atype}] {file_path}: {exc}")
            self.db.log_error(case_id, device_id, file_path, atype, str(exc))
            with self._lock:
                self._result.errors.append(f"{file_path}: {exc}")
            return

        if records:
            self.db.insert_artifacts_bulk(records)
        if entities:
            self.db.insert_entities_bulk(entities)
        if timeline:
            self.db.insert_timeline_bulk(timeline)

        with self._lock:
            self._result.files_processed += 1
            self._result.artifact_counts[atype] = (
                self._result.artifact_counts.get(atype, 0) + len(records))

    def _save_report(self, case_dir: str) -> str:
        path = os.path.join(case_dir, "PARSER_REPORT.json")
        data = asdict(self._result)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, default=str)
        self.log.info(f"[PARSER] Report → {path}")
        return path


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def build_parser_cli() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="parser.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "HIVE Platform  —  Stage 2: Universal Evidence Parser  v"
            + HIVE_PARSER_VERSION + "\n"
            "Transforms raw collector.py evidence into structured intelligence.\n\n"
            "EVTX support:     pip install python-evtx\n"
            "Registry support: pip install python-registry"
        ),
        epilog="""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 QUICK-START EXAMPLES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Parse all devices in a case:
  python3 parser.py --evidence /evidence --case-id CASE-2024-001

Parse with 8 parallel workers:
  python3 parser.py --evidence /evidence --case-id CASE-2024-001 --workers 8

Parse a single device directory:
  python3 parser.py --device-dir /evidence/CASE-2024-001/android_ABC123_a1b2

Export evidence to JSON Lines after parsing:
  python3 parser.py --evidence /evidence --case-id CASE-2024-001 --export-json

Query the database after parsing:
  sqlite3 /evidence/CASE-2024-001/hive_evidence.db \\
    "SELECT entity_type, entity_value, COUNT(*) as n \\
       FROM entities GROUP BY entity_type, entity_value \\
     ORDER BY n DESC LIMIT 50"
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
    )
    g = p.add_argument_group("Input")
    g.add_argument("--evidence",   metavar="DIR",
                    help="HIVE evidence root (contains <case-id>/ subdirectory)")
    g.add_argument("--case-id",    metavar="ID",
                    help="Case identifier (subdirectory under --evidence)")
    g.add_argument("--device-dir", metavar="DIR",
                    help="Parse a single device directory (bypasses --evidence)")

    g2 = p.add_argument_group("Output")
    g2.add_argument("--db",          metavar="FILE",
                     help="Override output SQLite DB path")
    g2.add_argument("--export-json", action="store_true",
                     help="Export all tables to JSON Lines alongside the DB")

    g3 = p.add_argument_group("Operation")
    g3.add_argument("--workers",  type=int, default=DEFAULT_WORKERS,
                     help=f"Parallel device parsing threads (default: {DEFAULT_WORKERS})")
    g3.add_argument("--stats",    action="store_true",
                     help="Print database statistics and exit (DB must already exist)")
    g3.add_argument("-v","--verbose", action="store_true",
                     help="Debug-level logging")
    return p


def main() -> int:
    cli  = build_parser_cli()
    args = cli.parse_args()

    # Derive case directory
    if args.device_dir:
        case_dir = os.path.dirname(args.device_dir.rstrip("/"))
        case_id  = args.case_id or os.path.basename(case_dir)
    elif args.evidence and args.case_id:
        case_dir = os.path.join(args.evidence, args.case_id)
        case_id  = args.case_id
    else:
        cli.print_help()
        print("\n[!] Provide either --device-dir or both --evidence and --case-id")
        return 1

    if not os.path.isdir(case_dir):
        print(f"[!] Case directory not found: {case_dir}")
        return 1

    log = _setup_logging(case_dir, args.verbose)

    db_path = args.db or os.path.join(case_dir, "hive_evidence.db")
    db      = EvidenceDatabase(db_path)

    # --stats mode
    if args.stats:
        stats = db.stats()
        print(json.dumps(stats, indent=2))
        db.close()
        return 0

    log.info(f"HIVE parser v{HIVE_PARSER_VERSION}  |  Case: {case_id}")
    log.info(f"Database: {db_path}")
    log.info(f"EVTX support:     {'YES' if HAS_EVTX     else 'NO (pip install python-evtx)'}")
    log.info(f"Registry support: {'YES' if HAS_REGISTRY else 'NO (pip install python-registry)'}")

    hive = HIVEParser(db, workers=args.workers)

    if args.device_dir:
        result = hive.parse_single_device(args.device_dir, case_id)
    else:
        result = hive.parse_case(case_dir, case_id)

    if args.export_json:
        export_dir = os.path.join(case_dir, "json_export")
        paths = db.export_json(export_dir)
        log.info(f"JSON export → {export_dir}  ({len(paths)} files)")

    db.close()

    print("\n" + "─" * 50)
    print(f"  Devices parsed   : {result.devices_parsed}")
    print(f"  Files processed  : {result.files_processed}")
    print(f"  Records stored   : {result.records_parsed}")
    print(f"  Entities found   : {result.entities_found}")
    print(f"  Timeline events  : {result.timeline_events}")
    print(f"  Errors           : {len(result.errors)}")
    print(f"  Database         : {db_path}")
    print("─" * 50)
    return 0 if not result.errors else 2


if __name__ == "__main__":
    sys.exit(main())
