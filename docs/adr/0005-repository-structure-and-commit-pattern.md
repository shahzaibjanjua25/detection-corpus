# ADR-0005: Repository Structure and Commit Pattern

## Status
Accepted

## Context
A detection-as-code program benefits from a Git history that itself documents the evolution of each rule (scaffold → logic → filters → metadata). Flat dumps of complete rules hide that evolution and make code review harder.

## Decision
- Directory layout follows the master prompt (sigma by OS/tactic, yara by category, etc.).
- When materializing from generation blocks, apply:
  - Sigma / Correlation: 4 commits (scaffold → selection → filter+falsepositives → tags+level+status)
  - YARA: 5 commits (scaffold → strings → condition → meta → placement)
- Supporting artifacts (maps, hypotheses, tuning, lifecycle, ADRs) receive one commit each.
- Commit messages reference the rule `id` for traceability.

## Consequences
- Repository can grow to several thousand commits naturally.
- `git blame` and `git log --follow` become useful for understanding rule history.
- Requires a small materialization script; human authors may still commit complete rules in one change when appropriate.
