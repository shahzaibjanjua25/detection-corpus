# Lifecycle: corr_lnx_payload_retrieval_to_execution

| Date       | Status       | Change                                         | Justification |
|------------|--------------|------------------------------------------------|---------------|
| 2024-03-18 | experimental | Three rules authored (2 Sigma halves + 1 correlation) | Initial coverage, untested in production |

**Deployment note:** this is the first rule in the series that requires
**three artefacts deployed together**: the two underlying Sigma rules
(`proc_creation_lnx_payload_download_staging` and
`proc_creation_lnx_exec_from_staging`) and the correlation rule itself.
Deploying the correlation without the underlying rules produces no
alerts (the correlation has nothing to correlate). Deploying the
underlying rules without the correlation produces a flood of `level: low`
noise. **All three must ship together**, and the deployment pipeline must
enforce this dependency — if the Sigma rules are rolled back, the
correlation must be rolled back in the same change.

Promotion path: `experimental` → `test` after two weeks of shadow mode,
target < 3 FPs/day per 1,000 hosts on production. Expected FP sources on
production:
  - Legitimate installer/bootstrap scripts that download to /tmp and
    execute once (one-time per host; amortized low)
  - Kubernetes init containers and cloud-init on ephemeral hosts
    (correlated with instance launch; suppressible by instance-age
    filter)
  - Developer activity on dev/staging (high FP; allow exception, similar
    to Day 7's severity exception)

The 5-minute `timespan` is the primary tuning knob. If the fleet has
legitimate build tooling that regularly exceeds 5m between download and
exec, widen to 10m (at the cost of some adversary dwell). If the fleet
is tight and adversary dwell is typically sub-minute, narrow to 2m. The
`temporal_ordered` type is non-negotiable — do not change to unordered,
because unordered correlation would fire on coincidental (exec-then-
download) events that are almost always benign.

**Verification step beyond FP rate:** confirm that the fleet's
process-accounting pipeline captures **both** halves (command line and
executable path) with sufficient field fidelity for the correlation
group-by (`host.name`) to work. Some osquery deployments omit the host
name field or normalize it inconsistently, which silently breaks the
correlation (events from the same host would not group). Validate
end-to-end on a representative host by simulating a curl-to-tmp followed
by execution and confirming a single correlated alert fires.

**Split candidate:** if the FP rate is dominated by one half (usually
the execution half, due to build tooling), consider keeping the
download half at `low` and demoting the execution half to `informational`
(no alert, correlation-only). This preserves the correlation signal
without flooding the alert queue. The split should be documented in the
lifecycle record if adopted.
