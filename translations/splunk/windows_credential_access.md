# Windows Credential Access — Splunk translation notes

LSASS Memory Dump via Procdump or Similar Tools:
```
(Image="*\\procdump*.exe" CommandLine="*lsass*") OR
(Image="*\\rundll32.exe" CommandLine="*comsvcs.dll*MiniDump*")
| where NOT (ParentImage="*\\explorer.exe" AND CommandLine="*Sysinternals*")
```
caveats: Requires Sysmon or process creation logs with full CommandLine. Field names may be Image/CommandLine or process_name/process_command_line depending on TA.

Mimikatz Command Line Indicators:
```
CommandLine IN ("*sekurlsa::*", "*lsadump::*", "*privilege::debug*")
```
caveats: High signal; still filter research environments.
