# kafka-acl-audit

Audit Apache Kafka ACLs from kafka-acls output: flag wildcard principals and resources, overly broad operations, and duplicate or shadowed rules.

## Planned scope

Parse `kafka-acls --list` output (and a JSON form), report wildcard principals (User:*), wildcard/prefixed resources that grant too much, ALL/Write/Alter on cluster or all topics, deny rules that shadow allows, duplicates, and principals with no matching topic in an optional topic list. Exit codes for CI.
