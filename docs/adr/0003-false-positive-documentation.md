# ADR-0003: Mandatory False-Positive Documentation

## Status
Accepted

## Context
Rules without documented false positives are difficult to tune and frequently disabled by SOC teams. Undocumented FPs also hide systemic data-quality or process issues.

## Decision
- Every Sigma rule must list at least **two realistic false-positive scenarios**.
- Every correlation rule must list at least **one**.
- False positives should describe real operational conditions (admin tools, software updates, legitimate remote management, scheduled tasks, etc.), not generic statements.
- Tuning changes that suppress FPs are recorded in `tuning/<rule-slug>.md`.

## Consequences
- Higher initial authoring effort.
- Dramatically improved long-term maintainability and SOC trust.
- Tuning logs become a knowledge base for future rule authors.
