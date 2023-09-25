import json
from pathlib import Path

import pytest

from kafka_acl_audit.cli import main
from kafka_acl_audit.parser import Acl, ParseError, parse, parse_json, parse_text
from kafka_acl_audit.rules import audit

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def acl(name="orders", principal="User:alice", op="READ", perm="ALLOW",
        rtype="TOPIC", pattern="LITERAL", host="*"):
    return Acl(rtype, name, pattern, principal, host, op, perm)


def rules_for(findings):
    return sorted(f.rule for f in findings)


# --- parser -----------------------------------------------------------------

def test_parse_kafka_39_list_output():
    acls = parse_text((EXAMPLES / "kafka-acls-list.txt").read_text())
    assert len(acls) == 13
    payments = [a for a in acls if a.resource_name == "payments"]
    assert {a.permission for a in payments} == {"ALLOW", "DENY"}
    legacy = next(a for a in acls if a.principal == "User:legacy")
    assert legacy.host == "10.0.0.5"
    billing = next(a for a in acls if a.resource_name == "billing-")
    assert billing.pattern_type == "PREFIXED"
    cluster = next(a for a in acls if a.resource_type == "CLUSTER")
    assert cluster.resource_name == "kafka-cluster"


def test_parse_kafka_37_trailing_whitespace():
    # Kafka 3.7 prints "`: " and " \t(...) " with stray spaces.
    acls = parse_text((EXAMPLES / "kafka-acls-list-3.7.txt").read_text())
    assert len(acls) == 6
    assert {a.operation for a in acls if a.principal == "User:ops"} == {
        "CLUSTER_ACTION", "DESCRIBE"}


def test_parse_add_output_and_ignores_noise():
    text = (
        "2025-11-11 main ERROR Could not determine local host name\n"
        "\tat java.base/java.net.InetAddress.getLocalHost(Unknown Source)\n"
        "Adding ACLs for resource `ResourcePattern(resourceType=TOPIC, name=orders, "
        "patternType=LITERAL)`: \n"
        " \t(principal=User:alice, host=*, operation=DESCRIBE, permissionType=ALLOW)\n"
        "Removing ACLs for resource `ResourcePattern(resourceType=TOPIC, name=x, "
        "patternType=LITERAL)`: \n"
        "\t(principal=User:bob, host=*, operation=READ, permissionType=ALLOW)\n"
    )
    acls = parse_text(text)
    assert [(a.principal, a.resource_name) for a in acls] == [("User:alice", "orders")]


def test_parse_json_defaults_and_case():
    acls = parse_json(json.dumps({"acls": [
        {"resource_type": "topic", "resourceName": "t", "principal": "User:a",
         "operation": "read"}]}))
    assert acls[0].key == ("TOPIC", "t", "LITERAL", "User:a", "*", "READ", "ALLOW")


def test_parse_json_missing_field():
    with pytest.raises(ParseError, match="principal"):
        parse_json('[{"resourceType": "TOPIC", "name": "t", "operation": "READ"}]')


def test_parse_rejects_garbage():
    with pytest.raises(ParseError):
        parse("hello world\n")
    assert parse("") == []


# --- rules ------------------------------------------------------------------

def test_wildcard_principal_severity_depends_on_operation():
    read = audit([acl(principal="User:*")])
    write = audit([acl(principal="User:*", op="WRITE")])
    assert [(f.rule, f.severity) for f in read] == [("wildcard-principal", "medium")]
    assert [(f.rule, f.severity) for f in write] == [("wildcard-principal", "high")]


def test_wildcard_resource_and_short_prefix():
    assert rules_for(audit([acl(name="*", op="WRITE")])) == ["wildcard-resource"]
    short = audit([acl(name="a", pattern="PREFIXED")])
    assert [(f.rule, f.severity) for f in short] == [("wildcard-resource", "medium")]
    assert audit([acl(name="a", pattern="PREFIXED")], min_prefix=1) == []
    assert audit([acl(name="billing-", pattern="PREFIXED")]) == []


def test_cluster_alter_is_high_and_describe_is_fine():
    f = audit([acl(rtype="CLUSTER", name="kafka-cluster", op="ALTER")])
    assert [(x.rule, x.severity) for x in f] == [("broad-operation", "high")]
    assert audit([acl(rtype="CLUSTER", name="kafka-cluster", op="DESCRIBE")]) == []


def test_all_on_single_topic_is_medium():
    f = audit([acl(op="ALL")])
    assert [(x.rule, x.severity) for x in f] == [("broad-operation", "medium")]


def test_deny_shadows_allow_cases():
    allow = acl(principal="User:bob")
    assert rules_for(audit([allow, acl(principal="User:bob", perm="DENY")])) == [
        "deny-shadows-allow"]
    # deny ALL on a wildcard topic shadows a literal allow
    assert "deny-shadows-allow" in rules_for(
        audit([allow, acl(principal="User:bob", perm="DENY", op="ALL", name="*")]))
    # deny for User:* shadows everyone
    assert "deny-shadows-allow" in rules_for(
        audit([allow, acl(principal="User:*", perm="DENY", pattern="PREFIXED", name="ord")]))
    # deny from one host does not shadow an allow from all hosts
    assert audit([allow, acl(principal="User:bob", perm="DENY", host="10.0.0.1")]) == []
    # deny on a different operation does not shadow
    assert audit([allow, acl(principal="User:bob", perm="DENY", op="WRITE")]) == []


def test_duplicate_and_redundant():
    findings = audit([acl(), acl(), acl(op="DESCRIBE")])
    assert rules_for(findings) == ["duplicate", "redundant-allow"]
    # a prefixed allow covers a literal allow with the same prefix
    findings = audit([acl(name="analytics", pattern="PREFIXED"), acl(name="analytics.clicks")])
    assert rules_for(findings) == ["redundant-allow"]
    # but not one for a different principal or a name outside the prefix
    assert audit([acl(name="analytics", pattern="PREFIXED"),
                  acl(name="analytics.clicks", principal="User:bob"),
                  acl(name="billing")]) == []


def test_unknown_topics():
    acls = [acl(name="orders"), acl(name="gone"), acl(principal="User:old", name="legacy")]
    findings = audit(acls, topics=["orders"])
    sev = {f.acl.resource_name: f.severity for f in findings}
    assert sev == {"gone": "low", "legacy": "medium"}
    assert audit([acl(name="ord", pattern="PREFIXED")], topics=["orders"]) == []


# --- CLI --------------------------------------------------------------------

def test_cli_example_exit_code_and_text(capsys):
    rc = main([str(EXAMPLES / "kafka-acls-list.txt"), "--topics", str(EXAMPLES / "topics.txt")])
    out = capsys.readouterr().out
    assert rc == 1
    assert "13 ACLs checked, 8 findings (3 high, 3 medium, 2 low)" in out
    assert "deny-shadows-allow: ALLOW User:bob READ on TOPIC:payments" in out


def test_cli_json_and_fail_on(capsys):
    rc = main([str(EXAMPLES / "acls.json"), "--format", "json", "--fail-on", "high"])
    data = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert data["acls_checked"] == 5
    assert data["summary"] == {"low": 2, "medium": 3, "high": 0}


def test_cli_ignore_and_never(capsys):
    rc = main([str(EXAMPLES / "kafka-acls-list-3.7.txt"), "--fail-on", "never"])
    assert rc == 0
    capsys.readouterr()
    rc = main([str(EXAMPLES / "acls.json"), "--ignore", "wildcard-resource",
               "--ignore", "wildcard-principal"])
    assert rc == 0
    assert "wildcard" not in capsys.readouterr().out.split("ACLs checked")[0]


def test_cli_stdin(monkeypatch, capsys):
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO((EXAMPLES / "kafka-acls-list-3.7.txt").read_text()))
    assert main([]) == 1
    assert "6 ACLs checked" in capsys.readouterr().out


def test_cli_errors(tmp_path, capsys):
    assert main([str(tmp_path / "missing.txt")]) == 2
    bad = tmp_path / "bad.json"
    bad.write_text("[1, 2")
    assert main([str(bad)]) == 2
    assert "invalid JSON" in capsys.readouterr().err
