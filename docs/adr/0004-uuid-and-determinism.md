# ADR-0004: Deterministic Rule Identifiers

## Status
Accepted

## Context
Random UUIDs make it impossible to re-generate or verify rule identity across batch generations or when the same detection logic is re-authored later. Pipeline tooling needs stable identifiers.

## Decision
UUIDs are derived deterministically:

```
sha256(title + "|" + logsource.category + "|" + primary_technique)
```

The first 8 hex characters form the first segment, followed by fixed middle segments and the remaining hash material truncated to produce a valid UUIDv4-style string. The derivation method is recorded in `MANIFEST.json`.

Dates are constrained to the window 2024-01-01 → 2025-12-31 and increase monotonically within families.

## Consequences
- Identical input always produces the same UUID.
- Re-runs of generation do not create duplicate identities.
- Slight loss of pure randomness is accepted for auditability.
