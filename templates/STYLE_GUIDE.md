# DetectionForge Style Guide

## Naming

- **Sigma file slug**: lowercase, hyphens, descriptive of the observable (e.g. `proc_creation_powershell_encoded_command.yml`)
- **YARA rule name**: PascalCase, family + variant (e.g. `Malware_Emotet_Loader`)
- **Correlation slug**: `corr_<short-description>.yml`

## Titles

- Start with the subject (process, registry, network, etc.)
- Include the key observable
- Keep under 90 characters
- Example: `Suspicious PowerShell Encoded Command Execution`

## Descriptions

- One or two sentences maximum
- State what is being detected and why it is suspicious
- Do not repeat the title

## Logsource

Prefer the most specific combination that is still realistic:

```yaml
logsource:
  category: process_creation
  product: windows
```

Avoid inventing categories. Stick to SigmaHQ canonical categories.

## Detection Logic

- Prefer `selection` + `filter_*` pattern
- Use `condition: selection and not 1 of filter_*`
- Keep field names consistent with the logsource (Image, CommandLine, TargetObject, etc.)
- Prefer modifiers (`|contains`, `|endswith`, `|re`) over overly broad wildcards

## False Positives

Write concrete scenarios:

```yaml
falsepositives:
  - Legitimate software installers that embed Base64 payloads
  - Administrative scripts that intentionally use encoded PowerShell for obfuscation of credentials in transit
```

## Levels

| Level         | When to use                                      |
|---------------|--------------------------------------------------|
| informational | Purely observational / inventory                 |
| low           | Suspicious but frequently benign                 |
| medium        | Clear suspicious activity, moderate FP risk      |
| high          | Strong indicator of malicious intent             |
| critical      | Near-certain compromise or destructive action    |

## Tags

Always include:

```yaml
tags:
  - attack.<tactic>
  - attack.t####      # or attack.t####.###
```

Optionally add `detection.threat-hunting` or `detection.emerging-threats`.

## YARA Specifics

- Always include a `# PLACEMENT:` comment
- Prefer ASCII + wide when the string may appear in both
- Hex sequences for distinctive byte patterns
- Condition should be as specific as practical while remaining useful
- Include at least one hash in meta when a public sample is known; otherwise add `# REVIEW: no public sample hash available`

## Comments

Use YAML comments (`#`) for:

- REVIEW notes when confidence is low
- Placement guidance
- Short rationale that does not belong in the description
