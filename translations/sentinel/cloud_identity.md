# Cloud Identity — Microsoft Sentinel KQL notes

Azure AD Risky Sign-in Detected:
```
SigninLogs
| where ResultType == 0
| where RiskState in ("atRisk", "confirmedCompromised")
```
caveats: Requires Azure AD Identity Protection. Correlate with DeviceCompliance and Location for higher fidelity.

AWS Console Login Without MFA (via AWS connector or custom):
Map CloudTrail ConsoleLogin events where MFAUsed != Yes.
caveats: Ensure CloudTrail is ingested with additionalEventData.
