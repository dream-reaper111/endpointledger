"""Offline evidence inventory and bounded Windows/Linux timeline extraction."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo
from xml.etree import ElementTree

MAX_EVIDENCE = 512 * 1024 * 1024
MAX_ARTIFACT = 16 * 1024 * 1024
MAX_LINE = 256 * 1024
MAX_EVENTS = 1_000_000
BSD = re.compile(r"^(?:<\d{1,3}>)?(?P<stamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d)\s+(?P<host>\S+)\s+(?P<program>[^:\[]+)(?:\[\d+\])?:\s*(?P<message>.*)$")
RFC5424 = re.compile(r"^<\d{1,3}>1\s+(?P<stamp>\S+)\s+(?P<host>\S+)\s+(?P<program>\S+)\s+\S+\s+\S+\s+(?P<body>.*)$")
SSH_FAILURE = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)")
SSH_SUCCESS = re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+)")


class EvidenceError(ValueError):
    pass


def _utc(value: datetime) -> str:
    if value.tzinfo is None:
        raise EvidenceError("timestamp requires timezone")
    return value.astimezone(timezone.utc).isoformat()


@dataclass(frozen=True)
class Event:
    timestamp_utc: str
    original_timestamp: str
    host: str | None
    kind: str
    user: str | None
    source_ip: str | None
    event_id: str | None
    evidence_ref: str
    raw_sha256: str
    interpretation: str


def inventory(path: Path, origin: str) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_EVIDENCE:
        raise EvidenceError("evidence must be a regular file of at most 512 MiB")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return {"path": str(path), "origin": origin, "size": path.stat().st_size,
            "sha256": digest.hexdigest()}


def classify(message: str) -> tuple[str, str | None, str | None, str]:
    for kind, pattern in (("authentication_failure", SSH_FAILURE),
                          ("authentication_success", SSH_SUCCESS)):
        match = pattern.search(message)
        if match:
            try:
                address = str(ipaddress.ip_address(match.group("ip")))
            except ValueError:
                address = None
            return kind, match.group("user")[:256], address, "observed log text; authentication result not independently verified"
    if "sudo:" in message or message.startswith("sudo "):
        return "privilege_activity", None, None, "sudo activity recorded; authorization context not inferred"
    return "other", None, None, "observed log entry; no security conclusion"


def parse_syslog(path: Path, year: int, zone: str) -> tuple[list[Event], list[str]]:
    inventory(path, "supplied syslog")
    if not 1970 <= year <= 9999:
        raise EvidenceError("explicit year out of range")
    try:
        tz = ZoneInfo(zone)
    except KeyError as exc:
        raise EvidenceError("unknown timezone") from exc
    events = []
    issues = []
    with path.open("rb") as stream:
        for number, raw in enumerate(stream, 1):
            if number > MAX_EVENTS or len(raw) > MAX_LINE:
                raise EvidenceError("syslog record limit exceeded")
            line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            modern = RFC5424.match(line)
            old = BSD.match(line) if not modern else None
            if not modern and not old:
                issues.append(f"line {number}: unsupported syslog layout")
                continue
            match = modern or old
            stamp = match.group("stamp")
            try:
                if modern:
                    parsed = datetime.fromisoformat(stamp)
                    if parsed.tzinfo is None:
                        raise ValueError("timezone missing")
                    message = match.group("body")
                else:
                    parsed = datetime.strptime(f"{year} {stamp}", "%Y %b %d %H:%M:%S").replace(tzinfo=tz)
                    message = match.group("message")
            except ValueError:
                issues.append(f"line {number}: invalid timestamp")
                continue
            kind, user, source_ip, interpretation = classify(message)
            events.append(Event(_utc(parsed), stamp, match.group("host"), kind, user, source_ip,
                                None, f"{path.name}:line:{number}", hashlib.sha256(raw).hexdigest(),
                                interpretation))
    return events, issues


def parse_journal_json(path: Path) -> tuple[list[Event], list[str]]:
    inventory(path, "supplied journal JSON export")
    events = []
    issues = []
    with path.open("rb") as stream:
        for number, raw in enumerate(stream, 1):
            if number > MAX_EVENTS or len(raw) > MAX_LINE:
                raise EvidenceError("journal record limit exceeded")
            try:
                row = json.loads(raw)
                if not isinstance(row, dict):
                    raise ValueError("not an object")
                microseconds = int(row["__REALTIME_TIMESTAMP"])
                if microseconds < 0:
                    raise ValueError("negative timestamp")
                timestamp = datetime.fromtimestamp(microseconds / 1_000_000, timezone.utc)
                message = row.get("MESSAGE", "")
                if not isinstance(message, str):
                    message = ""
                kind, user, source_ip, interpretation = classify(message)
                events.append(Event(_utc(timestamp), str(row["__REALTIME_TIMESTAMP"]),
                                    str(row.get("_HOSTNAME", "")) or None, kind, user, source_ip,
                                    None, f"{path.name}:line:{number}", hashlib.sha256(raw).hexdigest(),
                                    interpretation))
            except (ValueError, KeyError, TypeError, OverflowError):
                issues.append(f"line {number}: invalid journal JSON record")
    return events, issues


def parse_evtx(path: Path) -> tuple[list[Event], list[str]]:
    inventory(path, "supplied EVTX")
    try:
        from Evtx.Evtx import Evtx
    except ImportError as exc:
        raise EvidenceError("python-evtx is unavailable; EVTX import not verified") from exc
    events = []
    issues = []
    with Evtx(str(path)) as log:
        for number, record in enumerate(log.records(), 1):
            if number > MAX_EVENTS:
                raise EvidenceError("EVTX record count limit exceeded")
            try:
                raw = record.data()
                xml = record.xml()
                if len(xml) > MAX_LINE:
                    raise ValueError("record XML too large")
                root = ElementTree.fromstring(xml)
                time_node = root.find(".//{*}TimeCreated")
                id_node = root.find(".//{*}EventID")
                computer = root.find(".//{*}Computer")
                if time_node is None or not time_node.get("SystemTime"):
                    raise ValueError("missing event timestamp")
                stamp = time_node.get("SystemTime")
                parsed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
                event_id = id_node.text if id_node is not None else None
                kind = {"4624": "authentication_success", "4625": "authentication_failure",
                        "4672": "privilege_activity", "7045": "service_installation_review"}.get(event_id, "other")
                user_node = root.find(".//{*}Data[@Name='TargetUserName']")
                events.append(Event(_utc(parsed), stamp, computer.text if computer is not None else None,
                                    kind, user_node.text[:256] if user_node is not None and user_node.text else None,
                                    None, event_id, f"{path.name}:record:{record.record_num()}",
                                    hashlib.sha256(raw).hexdigest(),
                                    "observed Windows event ID; activity interpretation requires analyst review"))
            except (ValueError, TypeError, ElementTree.ParseError, OverflowError):
                issues.append(f"record {number}: malformed or unsupported EVTX event")
    return events, issues


def inspect_startup_artifact(path: Path) -> list[dict]:
    item = inventory(path, "supplied startup artifact")
    if item["size"] > MAX_ARTIFACT:
        raise EvidenceError("startup artifact exceeds 16 MiB")
    markers = []
    for number, raw in enumerate(path.read_bytes().splitlines(), 1):
        if len(raw) > MAX_LINE:
            raise EvidenceError("startup artifact line exceeds limit")
        line = raw.decode("utf-8", errors="replace").strip()
        if line.startswith("@reboot ") or line.startswith("ExecStart="):
            markers.append({"reference": f"{path.name}:line:{number}",
                            "marker": "cron_at_reboot" if line.startswith("@reboot") else "systemd_exec_start",
                            "line_sha256": hashlib.sha256(raw).hexdigest(),
                            "interpretation": "startup configuration observed; maliciousness not inferred"})
    return markers


def build_report(files: list[tuple[Path, str]], analyst: str, origin: str,
                 year: int, zone: str) -> dict:
    if not 1 <= len(analyst) <= 128 or not 1 <= len(origin) <= 256 or not files:
        raise EvidenceError("analyst, origin, and evidence files are required")
    inventories = []
    events = []
    markers = []
    issues = []
    custody = []
    prev_hash = "0" * 64
    analyzed_at = _utc(datetime.now(timezone.utc))
    for path, kind in files:
        item = inventory(path, origin)
        inventories.append(item)
        entry = {"action": "analysis_input_registered", "at": analyzed_at,
                 "analyst": analyst, "evidence_sha256": item["sha256"],
                 "previous_hash": prev_hash}
        prev_hash = hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()
        entry["record_hash"] = prev_hash
        custody.append(entry)
        if kind == "syslog":
            found, notes = parse_syslog(path, year, zone)
        elif kind == "journal":
            found, notes = parse_journal_json(path)
        elif kind == "evtx":
            found, notes = parse_evtx(path)
        elif kind == "artifact":
            found, notes = [], []
            markers.extend(inspect_startup_artifact(path))
        else:
            raise EvidenceError("unsupported evidence type")
        if inventory(path, origin)["sha256"] != item["sha256"]:
            raise EvidenceError("evidence changed during analysis")
        events.extend(found)
        issues.extend(notes)
        if len(events) > MAX_EVENTS:
            raise EvidenceError("aggregate event count limit exceeded")
    return {"schema_version": 1, "analyst": analyst, "origin": origin,
            "analyzed_at": analyzed_at, "evidence": inventories, "custody_records": custody,
            "timeline": [asdict(event) for event in sorted(events, key=lambda item: item.timestamp_utc)],
            "startup_artifact_markers": markers, "issues": issues,
            "qualification": "technical audit trail only; not legal chain-of-custody certification"}
