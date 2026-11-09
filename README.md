# DetectionForge

**Detection-as-Code repository** — Sigma, correlation, and YARA rules with ATT&CK mapping, false-positive documentation, lifecycle tracking, SIEM translation notes, and Architecture Decision Records.

This corpus was built to the quality gates and structure defined in the DetectionForge master prompt. It contains both **curated high-fidelity rules** and a large set of **experimental volume rules** used for coverage, pipeline, and Git-history experiments.

---

## Rule Collections

Rules are organized by platform and format. The collection grows over time; browse `sigma/`, `correlation/`, and `yara/` for the current rules. `MANIFEST.json` contains repository metadata.

Coverage spans MITRE ATT&CK tactics. YARA rules cover malware families, packers, webshells, and threat hunting.
