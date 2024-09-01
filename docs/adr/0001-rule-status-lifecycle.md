# ADR-0001: Rule Status Lifecycle

## Status
Accepted

## Context
Detection content must move through controlled states so that experimental rules do not generate production noise while still allowing rapid iteration. Operators need a clear, auditable path from research to stable production use and eventual deprecation.

## Decision
Every rule carries a `status` field with one of four values:

- `experimental` — newly authored, limited validation, may produce high false positives
- `test` — validated in a non-production or canary environment, tuning in progress
- `stable` — production-ready, false-positive rate accepted, actively maintained
- `deprecated` — no longer recommended; kept for historical reference only

Transitions are recorded in `docs/lifecycle/` and require a short justification.

## Consequences
- CI can gate promotion (e.g., experimental rules cannot be deployed to prod SIEM without override).
- Tuning and lifecycle files provide an audit trail.
- Deprecated rules remain searchable for threat-hunting historical analysis.
