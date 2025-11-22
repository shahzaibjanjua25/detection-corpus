# Tuning log: PowerShell Encoded Command Execution

| Date       | Change                                      | Reason                                      | Author         |
| ---------- | ------------------------------------------- | ------------------------------------------- | -------------- |
| 2024-02-20 | Initial rule                                | Baseline detection                          | DetectionForge |
| 2024-06-12 | Added filter for TiWorker / TrustedInstaller| High FP volume from Windows Update          | DetectionForge |
| 2025-01-10 | Added SCCM ccmexec parent filter            | Deployment noise in enterprise environment  | DetectionForge |
