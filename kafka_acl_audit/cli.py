"""Command-line interface for kafka-acl-audit."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter

from . import __version__
from .parser import Acl, ParseError, parse
from .rules import RULES, SEVERITIES, Finding, audit

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def _read(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _load_topics(path: str) -> list[str]:
    topics = []
    for line in _read(path).splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            topics.append(line)
    return topics


def format_text(acls: list[Acl], findings: list[Finding]) -> str:
    lines = []
    for f in findings:
        lines.append(f"[{f.severity.upper():<6}] {f.rule}: {f.acl.describe()}")
        lines.append(f"         {f.message}  ({f.acl.source})")
    counts = Counter(f.severity for f in findings)
    summary = ", ".join(f"{counts.get(s, 0)} {s}" for s in reversed(SEVERITIES))
    if lines:
        lines.append("")
    lines.append(f"{len(acls)} ACLs checked, {len(findings)} findings ({summary})")
    return "\n".join(lines)


def format_json(acls: list[Acl], findings: list[Finding]) -> str:
    counts = Counter(f.severity for f in findings)
    return json.dumps(
        {
            "acls_checked": len(acls),
            "summary": {s: counts.get(s, 0) for s in SEVERITIES},
            "findings": [f.to_dict() for f in findings],
        },
        indent=2,
    )


def build_parser() -> argparse.ArgumentParser:
    rules_help = "\n".join(f"  {k:<20} {v}" for k, v in RULES.items())
    p = argparse.ArgumentParser(
        prog="kafka-acl-audit",
        description="Audit Kafka ACLs from `kafka-acls --list` output or JSON.",
        epilog=f"rules:\n{rules_help}\n\nexit codes: 0 clean, 1 findings at or "
        "above --fail-on, 2 usage or input error",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("files", nargs="*", default=["-"],
                   help="ACL files (text or JSON); '-' or nothing reads stdin")
    p.add_argument("--topics", metavar="FILE",
                   help="file with one existing topic name per line")
    p.add_argument("--format", choices=("text", "json"), default="text")
    p.add_argument("--fail-on", choices=SEVERITIES + ("never",), default="medium",
                   help="lowest severity that makes the exit code 1 (default: medium)")
    p.add_argument("--min-prefix-length", type=int, default=3, metavar="N",
                   help="flag PREFIXED patterns shorter than N characters (default: 3)")
    p.add_argument("--ignore", action="append", default=[], metavar="RULE",
                   choices=sorted(RULES), help="skip a rule (repeatable)")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    acls: list[Acl] = []
    try:
        for path in args.files:
            acls.extend(parse(_read(path), source="stdin" if path == "-" else path))
        topics = _load_topics(args.topics) if args.topics else None
    except (OSError, ParseError) as exc:
        print(f"kafka-acl-audit: error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    findings = [
        f for f in audit(acls, topics, args.min_prefix_length)
        if f.rule not in args.ignore
    ]
    out = format_json(acls, findings) if args.format == "json" else format_text(acls, findings)
    print(out)

    if args.fail_on == "never":
        return EXIT_OK
    threshold = SEVERITIES.index(args.fail_on)
    failing = any(SEVERITIES.index(f.severity) >= threshold for f in findings)
    return EXIT_FINDINGS if failing else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
