"""Parse ACLs from `kafka-acls --list` text output or a JSON document."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Acl:
    """One ACL binding: a resource pattern plus one access control entry."""

    resource_type: str
    resource_name: str
    pattern_type: str
    principal: str
    host: str
    operation: str
    permission: str
    source: str = ""

    @property
    def key(self) -> tuple:
        return (
            self.resource_type,
            self.resource_name,
            self.pattern_type,
            self.principal,
            self.host,
            self.operation,
            self.permission,
        )

    def describe(self) -> str:
        res = f"{self.resource_type}:{self.resource_name}"
        if self.pattern_type != "LITERAL":
            res += f" ({self.pattern_type})"
        return (
            f"{self.permission} {self.principal} {self.operation} on {res}"
            f" from host {self.host}"
        )

    def to_dict(self) -> dict:
        return {
            "resourceType": self.resource_type,
            "name": self.resource_name,
            "patternType": self.pattern_type,
            "principal": self.principal,
            "host": self.host,
            "operation": self.operation,
            "permissionType": self.permission,
        }


class ParseError(ValueError):
    pass


# Header lines printed by kafka-acls for --list ("Current ACLs for resource")
# and --add/--remove ("Adding ACLs for resource", "Removing ACLs ...").
_HEADER_RE = re.compile(
    r"ACLs for resource `ResourcePattern\("
    r"resourceType=(?P<type>[A-Z_]+), name=(?P<name>.*), "
    r"patternType=(?P<pattern>[A-Z_]+)\)`:\s*$"
)
_ENTRY_RE = re.compile(
    r"^\(principal=(?P<principal>.*), host=(?P<host>[^,]*), "
    r"operation=(?P<op>[A-Z_]+), permissionType=(?P<perm>[A-Z]+)\)$"
)


def parse_text(text: str, source: str = "") -> list[Acl]:
    """Parse the human-readable output of `kafka-acls --list`.

    Tolerates the leading/trailing whitespace differences between Kafka
    releases, stack traces or log lines mixed into the output, and the
    "Adding ACLs for resource" blocks printed by `kafka-acls --add`.
    """
    acls: list[Acl] = []
    current: tuple[str, str, str] | None = None
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        header = _HEADER_RE.search(line)
        if header:
            if line.startswith("Adding") or line.startswith("Current"):
                current = (header["type"], header["name"], header["pattern"])
            else:  # "Removing ACLs for resource ..." is not a grant
                current = None
            continue
        entry = _ENTRY_RE.match(line)
        if entry:
            if current is None:
                continue
            acls.append(
                Acl(
                    resource_type=current[0],
                    resource_name=current[1],
                    pattern_type=current[2],
                    principal=entry["principal"],
                    host=entry["host"],
                    operation=entry["op"],
                    permission=entry["perm"],
                    source=f"{source}:{lineno}" if source else f"line {lineno}",
                )
            )
            continue
        # Any other line (log output, "ACLs for principal ..." banner) ends
        # nothing; entries only follow their header, so just skip it.
    return acls


_JSON_KEYS = {
    "resource_type": ("resourceType", "resource_type"),
    "resource_name": ("name", "resourceName", "resource_name"),
    "pattern_type": ("patternType", "pattern_type"),
    "principal": ("principal",),
    "host": ("host",),
    "operation": ("operation",),
    "permission": ("permissionType", "permission_type", "permission"),
}
_JSON_DEFAULTS = {"pattern_type": "LITERAL", "host": "*", "permission": "ALLOW"}


def parse_json(text: str, source: str = "") -> list[Acl]:
    """Parse a JSON list of ACL bindings (or {"acls": [...]})."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ParseError(f"invalid JSON: {exc}") from exc
    if isinstance(data, dict):
        data = data.get("acls")
    if not isinstance(data, list):
        raise ParseError('JSON input must be a list of ACLs or {"acls": [...]}')
    acls = []
    for i, item in enumerate(data):
        if not isinstance(item, dict):
            raise ParseError(f"ACL #{i} is not an object")
        values = {}
        for field, names in _JSON_KEYS.items():
            value = next((item[n] for n in names if n in item), None)
            if value is None:
                value = _JSON_DEFAULTS.get(field)
            if value is None:
                raise ParseError(f"ACL #{i} is missing '{names[0]}'")
            values[field] = str(value)
        for field in ("resource_type", "pattern_type", "operation", "permission"):
            values[field] = values[field].upper()
        acls.append(Acl(**values, source=f"{source}#{i}" if source else f"#{i}"))
    return acls


def parse(text: str, source: str = "") -> list[Acl]:
    """Auto-detect JSON or kafka-acls text and parse it."""
    stripped = text.lstrip()
    if stripped.startswith("[") or stripped.startswith("{"):
        return parse_json(text, source)
    acls = parse_text(text, source)
    if not acls and stripped and "ACLs for resource" not in text:
        raise ParseError(
            "no ACLs found; expected `kafka-acls --list` output or JSON"
        )
    return acls
