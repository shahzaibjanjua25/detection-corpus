# ADR-0002: ATT&CK Mapping Discipline

## Status
Accepted

## Context
Loose ATT&CK tagging leads to inflated coverage metrics and makes prioritization difficult. Many open-source rule sets map multiple techniques to a single rule without clear justification, reducing the value of coverage matrices.

## Decision
- Each detection rule maps to **exactly one primary technique**.
- The primary technique is the one most directly observed by the detection logic.
- If a rule legitimately covers multiple techniques, either:
  - produce separate variant rules (distinct UUIDs), or
  - express the multi-stage relationship as a correlation rule.
- Secondary techniques may be noted in comments or hypothesis documents but never appear in the `tags` list of a Sigma/YARA rule unless they are the primary.

## Consequences
- Coverage matrices become trustworthy.
- Technique-level tuning and prioritization is possible.
- Slight increase in total rule count (acceptable trade-off).
