# Hypothesis: T1105 — Ingress Tool Transfer

## Statement
If an adversary has achieved initial execution on a Linux host but does
not yet have their tooling locally, their next move is to download the
tooling from an attacker-controlled host to a staging directory (/tmp,
/dev/shm, /var/tmp, /run/shm) and execute it. The staging-directory
choice is deliberate: /tmp and /dev/shm are world-writable, often mounted
with `noexec` disabled (surprisingly common on production fleets), and
frequently excluded from file-integrity monitoring because they are
expected to churn. The download+execute pattern is the standard
post-exploitation lifecycle: establish a foothold, fetch tooling, run it.

## Observable
A temporal correlation between two process_creation events on the same
host, within 5 minutes:
  (1) curl/wget/scp/rsync/sftp/tftp/ftp writing to a staging directory
  (2) execution of a binary whose path starts with a staging directory
The correlation requires **both** events to fire within the window; neither
alone is high-signal enough to fire at `high` severity.

## Why correlation, not a single rule
This is the first rule in the series that lives in `correlation/` rather
than `sigma/`, and the reasoning is instructive. Days 1–7 each detected
a single, unambiguous event (a write to a known-sensitive path, or a
command line matching a known pattern). This rule detects a *sequence*:
the download alone is too common (package managers, installer scripts,
CI/CD, developer work), and the execution alone is too common (build
outputs, test harnesses) — but the download *followed immediately by*
execution is a strong indicator of the T1105 → T1059.004 chain. This is
why correlation rules exist: to combine individually-weak signals into
a strong compound signal. The two underlying Sigma rules are shipped
with `level: low` (they are not meant to alert on their own); the
correlation rule promotes the compound to `high`.

## Telemetry prerequisite
Process creation with command line on the host, for both halves:
  - auditd EXECVE (`-a always,exit -F arch=b64 -S execve`), or
  - Sysmon for Linux (EventID 1), or
  - osquery process_events, or
  - Wazuh process monitoring, or
  - Falco / Tetragon / Tracee exec events.
**Important:** the correlation requires the same host to have *both*
events captured — if the download half is captured but the execution half
is missed (e.g., the execution happens via a mechanism that doesn't log),
the correlation fails silently. The underlying Sigma rules and the
correlation should be validated together on a representative fleet.

## Correlation logic detail
The correlation uses `type: temporal_ordered`, which requires the download
event to occur *before* the execution event (not just in either order
within the window). This is deliberate: execution-before-download is
almost always coincidental (a build tool that execs first, then downloads
a dependency), whereas download-before-execution is the T1105 pattern.
The `group-by: host.name` ensures the two events are correlated on the
same host; the `timespan: 5m` is a heuristic — legitimate build tooling
often has a longer window between download and exec (30s–2m for build
chains), while adversary tooling is typically faster (sub-second between
curl finishing and the binary running). 5 minutes is a compromise that
captures build-tool noise at the price of some adversary dwell; tune per
fleet.

## Why the correlation matters
If the fleet is already running Day 7 (reverse shell), the T1105
correlation is often the *first* signal in the chain: the adversary
downloads a tool, runs it, and the tool establishes the reverse shell.
Correlating the T1105 chain explicitly (rather than relying on the
reverse shell alert) gives the responder an earlier picture of the
intrusion — the download happens *before* the shell, so the responder
has a head start. This is the first rule in the series that is not just
"detect a thing" but "detect the beginning of the attack chain."

## Known blind spots
- **Download-then-execute via script** — an adversary who downloads a
  shell script to /tmp and runs `bash /tmp/script.sh` will not match
  the second half, because the executed binary is `bash`, not the
  script. The download-to-staging rule fires (the script path is in
  /tmp), but the execution rule does not (bash's Image is `/bin/bash`,
  not `/tmp/script.sh`). **Mitigation:** the correlation is still useful
  when paired with Day 7 (if the script eventually spawns a reverse
  shell), but the specific T1105 → T1059.004 chain is missed. A separate
  rule on `bash /tmp/*` execution is a plausible addition (planned).
- **Download via non-standard tools** — an adversary who downloads via
  a compiled binary (not curl/wget/scp/rsync) or via a language one-liner
  (`python -c "import urllib; ..."`) will not match the download rule.
  The file will still appear in /tmp and the execution rule may still
  fire — a partial catch — but the download half is missed. Network
  monitoring (outbound connections to unusual destinations) is the
  complement; out of scope for a host-side Sigma rule.
- **Download to a non-staging path** — an adversary who downloads to
  /opt, /home/user, or a hidden directory (/var/lib/.cache) evades the
  staging-directory assumption. The path choice is a heuristic, not a
  guarantee; a follow-on rule on unusual execution paths could catch
  this, but the current rule is scoped to staging directories.
- **In-memory execution** — a payload that is downloaded to memory and
  executed without touching disk (`curl ... | bash`, `memfd_create`)
  evades both halves of the rule. The `curl | bash` pattern is caught by
  Day 7's reverse-shell rule if the shell is a reverse shell, but a
  non-reverse-shell payload (e.g., a coin miner) is not caught. In-memory
  detection requires eBPF-level instrumentation (memfd_create monitoring),
  which is out of scope for this rule.
