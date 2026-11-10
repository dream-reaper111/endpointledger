"""Read-only, offline timeline export from explicitly supplied evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .core import EvidenceError, build_report


def main() -> None:
    parser = argparse.ArgumentParser(prog="endpointledger")
    parser.add_argument("--analyst", required=True)
    parser.add_argument("--origin", required=True, help="operator-provided evidence origin")
    parser.add_argument("--year", type=int, help="required for RFC 3164 syslog, which omits year")
    parser.add_argument("--timezone", default="UTC", help="IANA zone for RFC 3164 syslog")
    parser.add_argument("--syslog", type=Path, action="append", default=[])
    parser.add_argument("--journal-json", type=Path, action="append", default=[])
    parser.add_argument("--evtx", type=Path, action="append", default=[])
    parser.add_argument("--artifact", type=Path, action="append", default=[])
    args = parser.parse_args()
    if args.syslog and args.year is None:
        parser.error("--year is required for syslog; RFC 3164 lines omit it")
    files = ([(path, "syslog") for path in args.syslog]
             + [(path, "journal") for path in args.journal_json]
             + [(path, "evtx") for path in args.evtx]
             + [(path, "artifact") for path in args.artifact])
    try:
        report = build_report(files, args.analyst, args.origin, args.year or 1970, args.timezone)
    except (EvidenceError, OSError) as exc:
        parser.error(str(exc))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
