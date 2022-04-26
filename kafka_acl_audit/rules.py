"""Audit rules for Kafka ACL bindings."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from .parser import Acl

SEVERITIES = ("low", "medium", "high")

# Operations that let a principal change data, metadata or cluster state.
MUTATING_OPS = {
    "ALL",
    "WRITE",
    "CREATE",
    "DELETE",
    "ALTER",
    "ALTER_CONFIGS",
    "CLUSTER_ACTION",
    "IDEMPOTENT_WRITE",
}

# Cluster-level operations with a wide blast radius. ALTER on the cluster
# resource is what CreateAcls/DeleteAcls require, ALTER_CONFIGS changes broker
# configs, CLUSTER_ACTION is meant for inter-broker traffic only.
CLUSTER_SENSITIVE_OPS = {
    "ALL": "grants every cluster operation, including managing ACLs",
    "ALTER": "allows creating and deleting ACLs (and other cluster changes)",
    "ALTER_CONFIGS": "allows changing broker and cluster configs",
    "CLUSTER_ACTION": "is meant for inter-broker communication only",
}

# Kafka's authorizer treats an ALLOW for these operations as also allowing
# DESCRIBE (and ALTER_CONFIGS as allowing DESCRIBE_CONFIGS).
IMPLIES = {
    "READ": {"DESCRIBE"},
    "WRITE": {"DESCRIBE"},
    "DELETE": {"DESCRIBE"},
    "ALTER": {"DESCRIBE"},
    "ALTER_CONFIGS": {"DESCRIBE_CONFIGS"},
}


@dataclass
class Finding:
    rule: str
    severity: str
    message: str
    acl: Acl
    related: list[Acl] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "message": self.message,
            "acl": self.acl.to_dict(),
            "source": self.acl.source,
            "related": [a.to_dict() for a in self.related],
        }


RULES = {
    "wildcard-principal": "ALLOW granted to every principal (User:*)",
    "wildcard-resource": "ALLOW on every resource of a type, or a very short prefix",
    "broad-operation": "ALL operations, or sensitive operations on the cluster",
    "deny-shadows-allow": "an ALLOW that a DENY fully overrides",
    "duplicate": "the same ACL listed more than once",
    "redundant-allow": "an ALLOW already covered by a broader ALLOW",
    "unknown-topic": "topic ACL that matches no topic in the --topics list",
}


def _is_wildcard_principal(principal: str) -> bool:
    return principal == "*" or principal.endswith(":*")


def _is_wildcard_name(acl: Acl) -> bool:
    return acl.pattern_type == "LITERAL" and acl.resource_name == "*"


def resource_covers(outer: Acl, inner: Acl) -> bool:
    """True if every resource name matched by `inner` is matched by `outer`."""
    if outer.resource_type != inner.resource_type:
        return False
    if _is_wildcard_name(outer):
        return True
    if _is_wildcard_name(inner):
        return False
    if outer.pattern_type == "LITERAL":
        return inner.pattern_type == "LITERAL" and inner.resource_name == outer.resource_name
    if outer.pattern_type == "PREFIXED":
        return inner.resource_name.startswith(outer.resource_name)
    return False


def matches_topic(acl: Acl, topic: str) -> bool:
    if _is_wildcard_name(acl):
        return True
    if acl.pattern_type == "PREFIXED":
        return topic.startswith(acl.resource_name)
    return acl.resource_name == topic


def _principal_covers(outer: str, inner: str) -> bool:
    return outer == inner or _is_wildcard_principal(outer)


def _host_covers(outer: str, inner: str) -> bool:
    return outer == inner or outer == "*"


def _rule_wildcards(acl: Acl, min_prefix: int) -> list[Finding]:
    found = []
    if acl.permission != "ALLOW":
        return found
    if _is_wildcard_principal(acl.principal):
        sev = "high" if acl.operation in MUTATING_OPS else "medium"
        found.append(Finding(
            "wildcard-principal", sev,
            f"every principal, including User:ANONYMOUS, gets {acl.operation} on "
            f"{acl.resource_type}:{acl.resource_name}",
            acl,
        ))
    if acl.resource_type != "CLUSTER":
        if _is_wildcard_name(acl):
            sev = "high" if acl.operation in MUTATING_OPS else "medium"
            found.append(Finding(
                "wildcard-resource", sev,
                f"{acl.principal} gets {acl.operation} on every "
                f"{acl.resource_type.lower()}, including ones created later",
                acl,
            ))
        elif acl.pattern_type == "PREFIXED" and len(acl.resource_name) < min_prefix:
            found.append(Finding(
                "wildcard-resource", "medium",
                f"prefix '{acl.resource_name}' is shorter than {min_prefix} "
                f"characters and likely matches far more than intended",
                acl,
            ))
    return found


def _rule_broad_ops(acl: Acl) -> list[Finding]:
    if acl.permission != "ALLOW":
        return []
    if acl.resource_type == "CLUSTER" and acl.operation in CLUSTER_SENSITIVE_OPS:
        return [Finding(
            "broad-operation", "high",
            f"{acl.principal} has {acl.operation} on the cluster, which "
            f"{CLUSTER_SENSITIVE_OPS[acl.operation]}",
            acl,
        )]
    if acl.operation == "ALL" and not _is_wildcard_name(acl):
        return [Finding(
            "broad-operation", "medium",
            f"{acl.principal} has ALL operations (incl. DELETE and ALTER) on "
            f"{acl.resource_type}:{acl.resource_name}; grant only what it uses",
            acl,
        )]
    return []


def _deny_covers(deny: Acl, allow: Acl) -> bool:
    return (
        _principal_covers(deny.principal, allow.principal)
        and _host_covers(deny.host, allow.host)
        and deny.operation in (allow.operation, "ALL")
        and resource_covers(deny, allow)
    )


def _allow_covers(broad: Acl, narrow: Acl) -> bool:
    if broad.key == narrow.key:
        return False
    op_ok = (
        broad.operation == narrow.operation
        or broad.operation == "ALL"
        or narrow.operation in IMPLIES.get(broad.operation, set())
    )
    return (
        op_ok
        and broad.principal == narrow.principal
        and _host_covers(broad.host, narrow.host)
        and resource_covers(broad, narrow)
    )


def audit(
    acls: list[Acl],
    topics: list[str] | None = None,
    min_prefix: int = 3,
) -> list[Finding]:
    findings: list[Finding] = []
    seen: dict[tuple, Acl] = {}
    unique: list[Acl] = []
    for acl in acls:
        if acl.key in seen:
            findings.append(Finding(
                "duplicate", "low",
                f"duplicate of the ACL at {seen[acl.key].source}",
                acl, [seen[acl.key]],
            ))
            continue
        seen[acl.key] = acl
        unique.append(acl)

    allows = [a for a in unique if a.permission == "ALLOW"]
    denies = [a for a in unique if a.permission == "DENY"]

    for acl in unique:
        findings.extend(_rule_wildcards(acl, min_prefix))
        findings.extend(_rule_broad_ops(acl))

    for allow in allows:
        shadow = [d for d in denies if _deny_covers(d, allow)]
        if shadow:
            findings.append(Finding(
                "deny-shadows-allow", "medium",
                f"this ALLOW never takes effect: DENY {shadow[0].principal} "
                f"{shadow[0].operation} on {shadow[0].resource_type}:"
                f"{shadow[0].resource_name} overrides it (DENY always wins)",
                allow, shadow,
            ))
            continue
        broader = [b for b in allows if _allow_covers(b, allow)]
        # Two identical-scope rules can only cover each other if they are equal,
        # which the duplicate pass already removed.
        if broader:
            findings.append(Finding(
                "redundant-allow", "low",
                f"already granted by: {broader[0].describe()}",
                allow, broader,
            ))

    if topics is not None:
        findings.extend(_rule_unknown_topics(unique, topics))

    order = {s: i for i, s in enumerate(reversed(SEVERITIES))}
    position = {id(a): i for i, a in enumerate(acls)}
    findings.sort(key=lambda f: (order[f.severity], f.rule, position.get(id(f.acl), 0)))
    return findings


def _rule_unknown_topics(acls: list[Acl], topics: list[str]) -> list[Finding]:
    findings = []
    hits_by_principal: dict[str, list[bool]] = defaultdict(list)
    for acl in acls:
        if acl.resource_type != "TOPIC":
            continue
        hit = any(matches_topic(acl, t) for t in topics)
        if acl.permission == "ALLOW":
            hits_by_principal[acl.principal].append(hit)
        if not hit:
            findings.append(Finding(
                "unknown-topic", "low",
                f"{acl.resource_name!r} ({acl.pattern_type.lower()}) matches no "
                f"topic in the topic list; stale ACL or typo?",
                acl,
            ))
    orphaned = {p for p, hits in hits_by_principal.items() if not any(hits)}
    for f in findings:
        if f.acl.permission == "ALLOW" and f.acl.principal in orphaned:
            f.severity = "medium"
            f.message += f" None of {f.acl.principal}'s topic ALLOW rules match a topic."
    return findings
