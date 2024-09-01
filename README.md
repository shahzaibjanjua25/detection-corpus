# DetectionForge

**Detection-as-Code repository** — Sigma, correlation, and YARA rules with ATT&CK mapping, false-positive documentation, lifecycle tracking, SIEM translation notes, and Architecture Decision Records.

This corpus was built to the quality gates and structure defined in the DetectionForge master prompt. It contains both **curated high-fidelity rules** and a large set of **experimental volume rules** used for coverage, pipeline, and Git-history experiments.

---

## Current Coverage

**2,500+ detection rules** across Sigma (Windows, Linux, Network, Cloud), Sigma correlation, and YARA.

| Category                          | Coverage        |
|-----------------------------------|-----------------|
| **Sigma (Windows)**               | 2,500+          |
| **Sigma (Linux)**                 | 10+             |
| **Sigma (Network)**               | 4+              |
| **Sigma (Cloud – AWS/Azure/GCP)** | 6+              |
| **Correlation rules**             | 12+             |
| **YARA**                          | 160+            |
| **Total detection rules**         | **2,500+**      |

Coverage spans all major MITRE ATT&CK tactics. Windows Sigma rules are organized by tactic and include credential access, execution, persistence, privilege escalation, defense evasion, discovery, lateral movement, collection, exfiltration, and command and control.

YARA coverage includes malware families, packers, webshells, and threat-hunting artifacts.

The authoritative live count is always available with:

```bash
find sigma -name "*.yml" | wc -l        # Sigma
find yara  -name "*.yar" | wc -l        # YARA
find correlation -name "*.yml" | wc -l  # Correlation