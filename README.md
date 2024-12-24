# kafka-acl-audit

Audit Apache Kafka ACLs from `kafka-acls --list` output: wildcard principals and resources, overly broad operations, DENY rules that make an ALLOW useless, duplicates, redundant grants and ACLs for topics that no longer exist.

**Status:** v0.1. Parses `kafka-acls` text output (checked against real Kafka 3.7.0 and 3.9.0 output) and a simple JSON form, runs seven audit rules, prints text or JSON, and sets an exit code you can gate CI on. It works offline on files; it never connects to a cluster.

## Install

```bash
pip install git+https://github.com/narayana006/kafka-acl-audit
```

Python 3.10+, no runtime dependencies.

## Quick start

`examples/kafka-acls-list.txt` is real output captured from a throwaway single-node Kafka 3.9.0 container with a few deliberately bad ACLs added:

```bash
kafka-acl-audit examples/kafka-acls-list.txt --topics examples/topics.txt
```

```text
[HIGH  ] broad-operation: ALLOW User:ops ALTER on CLUSTER:kafka-cluster from host *
         User:ops has ALTER on the cluster, which allows creating and deleting ACLs (and other cluster changes)  (examples/kafka-acls-list.txt:8)
[HIGH  ] wildcard-resource: ALLOW User:etl ALL on TOPIC:* from host *
         User:etl gets ALL on every topic, including ones created later  (examples/kafka-acls-list.txt:5)
[HIGH  ] wildcard-resource: ALLOW User:txn-app WRITE on TRANSACTIONAL_ID:* from host *
         User:txn-app gets WRITE on every transactional_id, including ones created later  (examples/kafka-acls-list.txt:34)
[MEDIUM] deny-shadows-allow: ALLOW User:bob READ on TOPIC:payments from host *
         this ALLOW never takes effect: DENY User:bob READ on TOPIC:payments overrides it (DENY always wins)  (examples/kafka-acls-list.txt:14)
[MEDIUM] unknown-topic: ALLOW User:legacy WRITE on TOPIC:old-topic from host 10.0.0.5
         'old-topic' (literal) matches no topic in the topic list; stale ACL or typo? None of User:legacy's topic ALLOW rules match a topic.  (examples/kafka-acls-list.txt:27)
[MEDIUM] wildcard-principal: ALLOW User:* READ on TOPIC:public-events from host *
         every principal, including User:ANONYMOUS, gets READ on TOPIC:public-events  (examples/kafka-acls-list.txt:24)
[LOW   ] redundant-allow: ALLOW User:carol READ on TOPIC:analytics.clicks from host *
         already granted by: ALLOW User:carol READ on TOPIC:analytics (PREFIXED) from host *  (examples/kafka-acls-list.txt:21)
[LOW   ] redundant-allow: ALLOW User:alice DESCRIBE on TOPIC:orders from host *
         already granted by: ALLOW User:alice READ on TOPIC:orders from host *  (examples/kafka-acls-list.txt:30)

13 ACLs checked, 8 findings (3 high, 3 medium, 2 low)
```

Exit code: `1`, because there are findings at or above the default `--fail-on medium`.

## Getting the input

Run `kafka-acls` yourself, with whatever client config your cluster needs, and save the output:

```bash
kafka-acls.sh --bootstrap-server broker:9092 --command-config admin.properties --list > acls.txt
kafka-topics.sh --bootstrap-server broker:9092 --command-config admin.properties --list > topics.txt
kafka-acl-audit acls.txt --topics topics.txt
```

The parser reads the `Current ACLs for resource ...` blocks (and `Adding ACLs for resource ...` blocks from `--add` output), ignores log lines and stack traces mixed into the output, and tolerates the stray whitespace that Kafka 3.x prints. Output of `--list --principal User:x` works too. You can pass several files; they are audited together, which is how duplicates across files show up.

The principal running `kafka-acls --list` needs `DESCRIBE` on the `CLUSTER` resource (the DescribeAcls API). `kafka-topics --list` returns only topics that principal may describe, so use an admin principal for the topic list or `unknown-topic` findings will be wrong.

### JSON input

Kafka has no JSON output for ACLs, so this tool accepts its own simple form, either a list or `{"acls": [...]}`. Field names follow Kafka's `AclBinding` (camelCase or snake_case); `patternType` defaults to `LITERAL`, `host` to `*`, `permissionType` to `ALLOW`. `examples/acls.json` is a hand-written illustrative example:

```json
[
  {"resourceType": "TOPIC", "name": "orders", "patternType": "LITERAL",
   "principal": "User:orders-api", "host": "*", "operation": "WRITE", "permissionType": "ALLOW"}
]
```

## Rules

| Rule | Severity | What it flags |
|---|---|---|
| `wildcard-principal` | high for mutating ops, else medium | ALLOW to `User:*`, which matches every principal including `User:ANONYMOUS` on unauthenticated listeners |
| `wildcard-resource` | high for mutating ops, else medium | ALLOW on literal `*` (every topic/group/transactional id, now and later); PREFIXED patterns shorter than `--min-prefix-length` (medium) |
| `broad-operation` | high on CLUSTER, medium elsewhere | `ALL`, `ALTER`, `ALTER_CONFIGS` or `CLUSTER_ACTION` on the cluster resource; `ALL` on a single resource |
| `deny-shadows-allow` | medium | an ALLOW fully covered by a DENY for the same (or wildcard) principal, same or `*` host, same op or `ALL`, and a covering resource pattern |
| `duplicate` | low | the identical ACL listed twice (across files or in JSON) |
| `redundant-allow` | low | an ALLOW already granted by a broader ALLOW for the same principal (prefix or `*` resource, `ALL`, or Kafka's implied `DESCRIBE` from `READ`/`WRITE`/`DELETE`/`ALTER` and `DESCRIBE_CONFIGS` from `ALTER_CONFIGS`) |
| `unknown-topic` | low, medium if none of the principal's topic ALLOWs match | topic ACL that matches no topic in `--topics` |

"Mutating" operations are `ALL`, `WRITE`, `CREATE`, `DELETE`, `ALTER`, `ALTER_CONFIGS`, `CLUSTER_ACTION` and `IDEMPOTENT_WRITE`.

## Usage

```text
kafka-acl-audit [files ...] [--topics FILE] [--format text|json]
                [--fail-on low|medium|high|never] [--min-prefix-length N]
                [--ignore RULE]...
```

- No file or `-` reads stdin: `kafka-acls.sh ... --list | kafka-acl-audit`
- `--format json` prints `acls_checked`, a per-severity `summary` and every finding with the ACL, its source line and the related rules.
- `--ignore deny-shadows-allow --ignore redundant-allow` skips rules.

Exit codes: `0` no findings at or above `--fail-on`; `1` findings; `2` bad arguments, unreadable file or unparseable input.

## Features

- [x] Parse `kafka-acls --list` text output (Kafka 3.x and 4.x formats)
- [x] Parse a JSON list of ACL bindings
- [x] Wildcard principals, wildcard resources, very short prefixes
- [x] `ALL` and sensitive cluster operations
- [x] DENY rules that shadow ALLOW rules
- [x] Duplicate and redundant ALLOW rules
- [x] ACLs that match no topic in a supplied topic list
- [x] Text and JSON output, CI exit codes
- [ ] Read ACLs directly through the Admin API
- [ ] Per-rule severity overrides from a config file
- [ ] Baseline file to accept known findings

## Limitations

- Offline only: you supply the `kafka-acls` output.
- Host matching is exact string or `*`; the tool does not reason about IP ranges.
- Resource patterns are `LITERAL` and `PREFIXED` (what `kafka-acls --list` prints). `MATCH`/`ANY` are filter types, not stored patterns, and are not interpreted.
- Shadowing considers single DENY rules; it does not combine several partial DENYs.
- `redundant-allow` only compares rules for the same principal; it does not check group membership or custom principal builders.
- Severities are opinions. Use `--ignore` and `--fail-on` to fit your policy.

## Contributing

Issues and pull requests are welcome. Please add a test for any new rule or input format, and include a real (anonymised) `kafka-acls` snippet if you hit a parsing problem.

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

Built and maintained by [Narayana Vemburaj](https://github.com/narayana006).

Licensed under the [MIT License](LICENSE).
