# EndpointLedger

EndpointLedger is an offline, read-only endpoint evidence timeline tool. It inventories explicitly supplied evidence files with SHA-256 hashes, normalizes Linux syslog and `journalctl --output=json` exports, optionally parses Windows EVTX through `python-evtx`, records simple startup artifact markers, and produces a timestamp-sorted JSON report. It never executes captured commands or binaries and never changes source files.

## Run

Python 3.12+ is required. The Linux path uses only the standard library. EVTX requires the optional `python-evtx` package, which was unavailable for live validation here.

```bash
PYTHONPATH=. python3.12 -m endpointledger.cli --analyst analyst-name --origin 'authorized host export' --year 2026 --timezone America/Denver --syslog /path/to/auth.log > report.json
PYTHONPATH=. python3.12 -m endpointledger.cli --analyst analyst-name --origin 'authorized journal export' --journal-json /path/to/journal.jsonl > report.json
PYTHONPATH=. python3.12 -m endpointledger.cli --analyst analyst-name --origin 'authorized endpoint export' --evtx /path/to/Security.evtx --artifact /path/to/crontab > report.json
```

RFC 3164-style syslog omits the year and timezone, so both are explicit inputs rather than guessed. RFC 5424 timestamps must carry a timezone. The journal parser uses `__REALTIME_TIMESTAMP` microseconds from [systemd's JSON export format](https://systemd.io/JOURNAL_EXPORT_FORMATS). The EVTX adapter uses the documented [python-evtx record API](https://github.com/williballenthin/python-evtx/blob/master/Evtx/Evtx.py), but its live behavior is **not verified** here. The parser classifies selected SSH authentication messages and Windows event IDs as observed log records; it does not conclude compromise.

The report contains file hashes and sizes, origin supplied by the analyst, analysis time, a hash-linked custody metadata list, timeline events with per-record hashes, and parse issues. It deliberately omits raw messages and startup commands. This is a technical audit trail, not legal chain-of-custody certification. Preserve originals separately in approved evidence storage.

## Limits and next steps

Evidence files are limited to 512 MiB, startup artifacts to 16 MiB, individual lines to 256 KiB, and event counts to one million. Binary journald files, Windows Registry hives, scheduled-task XML, process trees, and full service inventories are not supported in this first milestone. No API, database, or dashboard exists yet because the offline evidence path must be verified first.

```bash
python3.12 -m compileall -q endpointledger tests
python3.12 -m unittest discover -s tests -v
```

See [ARCHITECTURE.md](ARCHITECTURE.md), [SECURITY.md](SECURITY.md), and [VALIDATION_REPORT.md](VALIDATION_REPORT.md). Next: test against sanitized authorized EVTX and journal exports, add Registry hive and scheduled-task adapters using supported libraries, then add authenticated case storage with auditable custody events.
