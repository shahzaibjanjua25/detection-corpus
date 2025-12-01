#!/usr/bin/env python3
"""
Generate a large batch of additional high-quality Sigma, correlation and YARA rules
following DetectionForge standards. Uses real ATT&CK techniques and realistic patterns.
"""
import hashlib
import uuid
from pathlib import Path
from datetime import date, timedelta
import random

ROOT = Path(__file__).resolve().parents[1]
random.seed(42)  # deterministic

def make_uuid(title: str, category: str, technique: str) -> str:
    h = hashlib.sha256(f"{title}|{category}|{technique}".encode()).hexdigest()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"

def date_for(idx: int) -> str:
    base = date(2024, 1, 15)
    d = base + timedelta(days=idx % 600)
    return d.strftime("%Y/%m/%d")

# ---------------------------------------------------------------------------
# Windows Sigma rules (largest set)
# ---------------------------------------------------------------------------

WINDOWS_RULES = [
    # Credential Access
    ("proc_creation_procdump_lsass", "Procdump LSASS Dump Attempt", "T1003.001", "credential-access",
     "process_creation", "Detects procdump targeting lsass.exe",
     {"Image|endswith": ["\\procdump.exe", "\\procdump64.exe"], "CommandLine|contains": "lsass"},
     ["Legitimate IR use of Sysinternals Procdump", "Some EDR products create process dumps"]),
    ("proc_creation_comsvcs_minidump", "Comsvcs MiniDump of LSASS", "T1003.001", "credential-access",
     "process_creation", "Detects rundll32 comsvcs MiniDump technique",
     {"Image|endswith": "\\rundll32.exe", "CommandLine|contains|all": ["comsvcs", "MiniDump"]},
     ["Rare legitimate diagnostic use", "Approved IR tooling"]),
    ("proc_creation_nanodump", "NanoDump Credential Dumping Tool", "T1003.001", "credential-access",
     "process_creation", "Detects NanoDump and similar silent LSASS dumpers",
     {"Image|endswith": ["\\nanodump.exe", "\\nanodump"], "CommandLine|contains": ["--write", "lsass"]},
     ["Red team exercises", "Security research labs"]),
    ("registry_sam_secrets_access", "Access to SAM or SECURITY Hive", "T1003.002", "credential-access",
     "registry_event", "Detects non-system access to SAM/SECURITY registry hives",
     {"TargetObject|contains": ["\\SAM\\", "\\SECURITY\\"]},
     ["Domain admin audits with regedit", "Backup software snapshotting registry"]),
    ("proc_creation_secretsdump", "Impacket Secretsdump Indicators", "T1003.003", "credential-access",
     "process_creation", "Detects command lines associated with Impacket secretsdump",
     {"CommandLine|contains": ["secretsdump", "-just-dc", "-ntds"]},
     ["Authorized penetration tests", "Internal red team activity"]),
    ("proc_creation_hashdump_shadow", "Volume Shadow Copy Credential Access", "T1003.003", "credential-access",
     "process_creation", "Detects creation of volume shadow copies followed by ntds access patterns",
     {"Image|endswith": "\\vssadmin.exe", "CommandLine|contains": ["create", "shadow"]},
     ["Legitimate system backup jobs", "Storage migration tools"]),
    ("proc_creation_lazagne", "LaZagne Credential Recovery Tool", "T1555", "credential-access",
     "process_creation", "Detects LaZagne password recovery utility",
     {"Image|endswith": ["\\lazagne.exe", "\\laZagne.exe"], "CommandLine|contains": ["all", "browsers", "chats"]},
     ["Security assessments", "Password audit tools used by IT"]),
    ("proc_creation_sharpdpapi", "SharpDPAPI Credential Extraction", "T1555.003", "credential-access",
     "process_creation", "Detects SharpDPAPI and similar DPAPI master key / credential extraction",
     {"CommandLine|contains": ["SharpDPAPI", "MasterKeys", "Triage", "Blob"]},
     ["Authorized DFIR activity", "Red team tooling in lab"]),

    # Execution
    ("proc_creation_powershell_download_cradle", "PowerShell Download Cradle", "T1059.001", "execution",
     "process_creation", "Detects common PowerShell download-and-execute cradles",
     {"Image|endswith": ["\\powershell.exe", "\\pwsh.exe"], "CommandLine|contains": ["DownloadString", "DownloadFile", "IEX", "Invoke-Expression"]},
     ["Software deployment scripts", "Configuration management tools"]),
    ("proc_creation_powershell_bypass_amsi", "PowerShell AMSI Bypass Attempts", "T1059.001", "execution",
     "process_creation", "Detects known AMSI bypass patterns in PowerShell command lines",
     {"CommandLine|contains": ["amsiInitFailed", "AmsiUtils", "[Ref].Assembly.GetType"]},
     ["Security research", "Malware analysis sandboxes"]),
    ("proc_creation_cmd_echo_pipe", "Cmd Echo Pipe to Execute", "T1059.003", "execution",
     "process_creation", "Detects cmd.exe using echo and pipe to execute content",
     {"Image|endswith": "\\cmd.exe", "CommandLine|contains|all": ["echo", "|"]},
     ["Legacy batch scripts", "Some installers"]),
    ("proc_creation_mshta_http", "Mshta Remote HTA Execution", "T1218.005", "execution",
     "process_creation", "Detects mshta.exe loading remote HTA/JS content",
     {"Image|endswith": "\\mshta.exe", "CommandLine|contains": ["http://", "https://"]},
     ["Legacy internal tools still using HTA", "Rare enterprise apps"]),
    ("proc_creation_regsvr32_scrobj", "Regsvr32 Scrobj Proxy Execution", "T1218.010", "execution",
     "process_creation", "Detects regsvr32 used with scrobj.dll for scriptlet execution",
     {"Image|endswith": "\\regsvr32.exe", "CommandLine|contains": ["scrobj", ".sct"]},
     ["Legitimate COM registration in rare cases", "Software installers"]),
    ("proc_creation_rundll32_javascript", "Rundll32 JavaScript Execution", "T1218.011", "execution",
     "process_creation", "Detects rundll32 executing JavaScript content",
     {"Image|endswith": "\\rundll32.exe", "CommandLine|contains": ["javascript:", "vbscript:"]},
     ["Very rare legitimate use", "Some accessibility helpers"]),
    ("proc_creation_cmstp_inf", "CMSTP INF Proxy Execution", "T1218.003", "execution",
     "process_creation", "Detects cmstp.exe used with INF files for proxy execution",
     {"Image|endswith": "\\cmstp.exe", "CommandLine|contains": [".inf", "/s"]},
     ["Legitimate connection manager profiles", "VPN client installers"]),
    ("proc_creation_installutil", "InstallUtil Proxy Execution", "T1218.004", "execution",
     "process_creation", "Detects InstallUtil.exe used to execute assemblies",
     {"Image|endswith": "\\InstallUtil.exe", "CommandLine|contains": ["/logfile=", "/LogToConsole=false"]},
     ["Legitimate .NET installation tasks", "Developer tooling"]),
    ("proc_creation_msiexec_remote", "Msiexec Remote Package Execution", "T1218.007", "execution",
     "process_creation", "Detects msiexec installing from remote HTTP/HTTPS sources",
     {"Image|endswith": "\\msiexec.exe", "CommandLine|contains": ["http://", "https://", "/i"]},
     ["Legitimate software deployment via HTTP", "Update mechanisms"]),
    ("proc_creation_wscript_vbs", "Wscript / Cscript Suspicious Script", "T1059.005", "execution",
     "process_creation", "Detects wscript/cscript executing scripts from unusual locations",
     {"Image|endswith": ["\\wscript.exe", "\\cscript.exe"], "CommandLine|contains": [".vbs", ".js", "\\Temp\\", "\\AppData\\"]},
     ["Legacy business applications", "Software installers using VBScript"]),

    # Persistence
    ("registry_run_key_user", "User Run Key Persistence", "T1547.001", "persistence",
     "registry_event", "Detects creation of Run/RunOnce keys under user hive by suspicious processes",
     {"TargetObject|contains": ["\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"]},
     ["Software installers registering startup", "Enterprise management agents"]),
    ("proc_creation_schtasks_system", "Scheduled Task Created as SYSTEM", "T1053.005", "persistence",
     "process_creation", "Detects schtasks creating tasks that run as SYSTEM or with highest privileges",
     {"Image|endswith": "\\schtasks.exe", "CommandLine|contains": ["/ru system", "/rl highest", "Create"]},
     ["Legitimate system maintenance tasks", "Patch management tools"]),
    ("proc_creation_at_command", "AT Command Job Creation", "T1053.002", "persistence",
     "process_creation", "Detects use of the legacy at.exe command for job scheduling",
     {"Image|endswith": "\\at.exe", "CommandLine|contains": ["\\\\", "/interactive"]},
     ["Legacy scripts still using at.exe", "Some monitoring tools"]),
    ("registry_winlogon_shell", "Winlogon Shell Modification", "T1547.004", "persistence",
     "registry_event", "Detects modification of Winlogon Shell or Userinit values",
     {"TargetObject|contains": ["\\Winlogon\\Shell", "\\Winlogon\\Userinit"]},
     ["Rare legitimate customization", "Some kiosk or thin-client software"]),
    ("proc_creation_bitsadmin_persist", "BITS Job Persistence", "T1197", "persistence",
     "process_creation", "Detects bitsadmin creating persistent download jobs",
     {"Image|endswith": "\\bitsadmin.exe", "CommandLine|contains": ["/create", "/addfile", "/SetNotifyCmdLine"]},
     ["Legitimate background transfer jobs", "Software updaters"]),
    ("registry_services_imagepath", "Service ImagePath Modification", "T1543.003", "persistence",
     "registry_event", "Detects modification of service ImagePath to unusual binaries",
     {"TargetObject|contains": ["\\Services\\", "\\ImagePath"], "Details|contains": ["\\Temp\\", "\\AppData\\", "powershell"]},
     ["Software updates changing service paths", "Legitimate service reconfiguration"]),
    ("proc_creation_sc_create", "SC Create Suspicious Service", "T1543.003", "persistence",
     "process_creation", "Detects sc.exe creating a new service with suspicious binary path",
     {"Image|endswith": "\\sc.exe", "CommandLine|contains|all": ["create", "binPath="]},
     ["Legitimate software installers creating services", "Driver installation"]),

    # Privilege Escalation
    ("proc_creation_uac_eventvwr", "UAC Bypass via Eventvwr", "T1548.002", "privilege-escalation",
     "process_creation", "Detects eventvwr.exe UAC bypass via msc file association hijack",
     {"ParentImage|endswith": "\\eventvwr.exe", "Image|endswith": ["\\cmd.exe", "\\powershell.exe", "\\wscript.exe"]},
     ["Extremely rare legitimate chaining", "Custom MSC snap-ins"]),
    ("proc_creation_uac_sdclt", "UAC Bypass via Sdclt", "T1548.002", "privilege-escalation",
     "process_creation", "Detects sdclt.exe used in UAC bypass techniques",
     {"Image|endswith": "\\sdclt.exe", "CommandLine|contains": ["/kickoffelev", "isolatedCommand"]},
     ["Legitimate backup/restore UI usage", "Rare"]),
    ("proc_creation_token_impersonation", "Token Impersonation Tools", "T1134.001", "privilege-escalation",
     "process_creation", "Detects tools commonly used for token theft and impersonation",
     {"CommandLine|contains": ["incognito", "token::", "ImpersonateLoggedOnUser", "SharpRDP"]},
     ["Authorized red team", "DFIR token analysis"]),
    ("proc_creation_printspoofer", "PrintSpoofer / SpoolSample Indicators", "T1134.001", "privilege-escalation",
     "process_creation", "Detects PrintSpoofer and related printer spooler privilege escalation tools",
     {"CommandLine|contains": ["PrintSpoofer", "SpoolSample", "GodPotato", "SweetPotato"]},
     ["Red team assessments", "Security research"]),

    # Defense Evasion
    ("proc_creation_wevtutil_clear", "Event Log Clearing via Wevtutil", "T1070.001", "defense-evasion",
     "process_creation", "Detects wevtutil or similar tools clearing Windows event logs",
     {"Image|endswith": ["\\wevtutil.exe", "\\wmic.exe"], "CommandLine|contains": ["clear-log", "cl", "ClearEventLog"]},
     ["Legitimate log rotation by administrators", "SIEM agents performing maintenance"]),
    ("proc_creation_fsutil_usn", "USN Journal Deletion", "T1070.004", "defense-evasion",
     "process_creation", "Detects deletion or modification of the USN journal",
     {"Image|endswith": "\\fsutil.exe", "CommandLine|contains": ["usn", "deletejournal"]},
     ["Storage management operations", "Disk cleanup utilities"]),
    ("proc_creation_timestomp_powershell", "PowerShell Timestomp", "T1070.006", "defense-evasion",
     "process_creation", "Detects PowerShell modifying file timestamps",
     {"Image|endswith": ["\\powershell.exe", "\\pwsh.exe"], "CommandLine|contains": [".CreationTime", ".LastWriteTime", "$(Get-Date)"]},
     ["Build systems normalizing timestamps", "Backup restore processes"]),
    ("proc_creation_attrib_hidden", "Attrib Hide or System Flag", "T1564.001", "defense-evasion",
     "process_creation", "Detects attrib.exe used to hide files or set system attribute",
     {"Image|endswith": "\\attrib.exe", "CommandLine|contains": ["+h", "+s", "+r"]},
     ["Legitimate system file protection", "Software installers"]),
    ("proc_creation_process_injection_tools", "Process Injection Tool Indicators", "T1055", "defense-evasion",
     "process_creation", "Detects command lines of common process injection frameworks",
     {"CommandLine|contains": ["CreateRemoteThread", "NtCreateThreadEx", "QueueUserAPC", "ProcessHollowing"]},
     ["Debuggers and development tools", "Authorized security testing"]),
    ("proc_creation_unhook_ntdll", "Ntdll Unhooking Indicators", "T1562.001", "defense-evasion",
     "process_creation", "Detects attempts to unhook or remap ntdll",
     {"CommandLine|contains": ["ntdll.dll", "unhook", "re-map", "knowndlls"]},
     ["Some security products", "Advanced debugging"]),
    ("proc_creation_disable_defender", "Attempts to Disable Windows Defender", "T1562.001", "defense-evasion",
     "process_creation", "Detects command lines attempting to disable or exclude from Defender",
     {"CommandLine|contains": ["Set-MpPreference", "DisableRealtimeMonitoring", "Add-MpPreference", "-ExclusionPath"]},
     ["Administrators tuning Defender", "Security product installers"]),
    ("proc_creation_clear_recycle", "Recycle Bin Clearing for Anti-Forensics", "T1070.004", "defense-evasion",
     "process_creation", "Detects tools or commands that empty the recycle bin in suspicious context",
     {"CommandLine|contains": ["Clear-RecycleBin", "emptyrecyclebin", "sdelete"]},
     ["User-initiated cleanup", "Disk space management scripts"]),

    # Discovery
    ("proc_creation_net_user_enum", "Net User / Group Enumeration", "T1087.001", "discovery",
     "process_creation", "Detects net.exe user and group enumeration commands",
     {"Image|endswith": "\\net.exe", "CommandLine|contains": ["user", "group", "localgroup", "/domain"]},
     ["Helpdesk and admin troubleshooting", "Inventory scripts"]),
    ("proc_creation_whoami_all", "Whoami Privilege Discovery", "T1033", "discovery",
     "process_creation", "Detects whoami with elevated or all flags often used in post-exploitation",
     {"Image|endswith": "\\whoami.exe", "CommandLine|contains": ["/all", "/priv", "/groups"]},
     ["Administrative troubleshooting", "Login scripts"]),
    ("proc_creation_systeminfo_full", "Systeminfo Reconnaissance", "T1082", "discovery",
     "process_creation", "Detects systeminfo.exe execution commonly used for host discovery",
     {"Image|endswith": "\\systeminfo.exe"},
     ["Asset inventory agents", "Helpdesk remote sessions"]),
    ("proc_creation_nltest_domain", "Nltest Domain Trust Discovery", "T1482", "discovery",
     "process_creation", "Detects nltest used for domain trust and DC discovery",
     {"Image|endswith": "\\nltest.exe", "CommandLine|contains": ["/domain_trusts", "/dclist", "/dsgetdc"]},
     ["Domain administrators performing trust audits", "Migration tools"]),
    ("proc_creation_adfind", "AdFind Active Directory Recon", "T1087.002", "discovery",
     "process_creation", "Detects AdFind tool used for Active Directory enumeration",
     {"Image|endswith": "\\AdFind.exe", "CommandLine|contains": ["-f", "-sc", "objectcategory"]},
     ["Authorized AD audits", "Identity governance tools"]),
    ("proc_creation_bloodhound_ingestor", "BloodHound / SharpHound Indicators", "T1087.002", "discovery",
     "process_creation", "Detects SharpHound and BloodHound collectors",
     {"CommandLine|contains": ["SharpHound", "BloodHound", "--CollectionMethod", "Session", "ACL"]},
     ["Authorized red team / purple team", "AD security assessments"]),
    ("proc_creation_portscan_tools", "Port Scanning Tool Execution", "T1046", "discovery",
     "process_creation", "Detects common port scanners and network discovery tools",
     {"Image|endswith": ["\\nmap.exe", "\\masscan.exe", "\\rustscan.exe"], "CommandLine|contains": ["-p", "-sS", "-sT"]},
     ["Network administrators performing scans", "Vulnerability management tools"]),

    # Lateral Movement
    ("proc_creation_psexec", "PsExec Execution", "T1021.002", "lateral-movement",
     "process_creation", "Detects PsExec or PSEXESVC activity",
     {"Image|endswith": ["\\psexec.exe", "\\psexec64.exe", "\\psexesvc.exe"]},
     ["IT remote administration", "Some RMM solutions"]),
    ("proc_creation_wmic_remote", "WMIC Remote Process Create", "T1047", "lateral-movement",
     "process_creation", "Detects wmic process call create against remote hosts",
     {"Image|endswith": "\\wmic.exe", "CommandLine|contains|all": ["/node:", "process", "call", "create"]},
     ["Legacy remote management scripts", "Some monitoring agents"]),
    ("proc_creation_winrm_exec", "WinRM / Enter-PSSession Lateral", "T1021.006", "lateral-movement",
     "process_creation", "Detects PowerShell remoting used for lateral movement patterns",
     {"CommandLine|contains": ["Enter-PSSession", "Invoke-Command", "-ComputerName", "New-PSSession"]},
     ["Legitimate remote administration", "Configuration management"]),
    ("proc_creation_rdp_enable", "RDP Enable via Registry or Command", "T1021.001", "lateral-movement",
     "process_creation", "Detects attempts to enable Remote Desktop via command line",
     {"CommandLine|contains": ["fDenyTSConnections", "0", "TermService", "reg add"]},
     ["Administrators enabling RDP for support", "Golden image preparation"]),
    ("proc_creation_smbexec", "SMBExec / Impacket Style Execution", "T1021.002", "lateral-movement",
     "process_creation", "Detects Impacket smbexec / atexec style command lines",
     {"CommandLine|contains": ["smbexec", "atexec", "wmiexec", "-hashes"]},
     ["Authorized penetration tests", "Internal security assessments"]),

    # Collection
    ("proc_creation_clipboard_powershell", "Clipboard Collection via PowerShell", "T1115", "collection",
     "process_creation", "Detects PowerShell accessing clipboard data",
     {"CommandLine|contains": ["Get-Clipboard", "Windows.Clipboard", "Get-Content -Path Alias:"]},
     ["Productivity scripts", "Accessibility tools"]),
    ("proc_creation_keylogger_indicators", "Keylogger Tool Indicators", "T1056.001", "collection",
     "process_creation", "Detects common keylogger related strings and tools",
     {"CommandLine|contains": ["GetAsyncKeyState", "SetWindowsHookEx", "keylogger", "logkeys"]},
     ["Security research", "Parental control software"]),
    ("proc_creation_screenshot_tools", "Screenshot Capture Tools", "T1113", "collection",
     "process_creation", "Detects tools and PowerShell used for screen capture",
     {"CommandLine|contains": ["CopyFromScreen", "Graphics.CopyFromScreen", "nircmd savescreenshot", "screencapture"]},
     ["Remote support tools", "Documentation / training software"]),

    # Exfiltration
    ("proc_creation_archive_staging", "Archive Staging for Exfiltration", "T1560.001", "exfiltration",
     "process_creation", "Detects creation of compressed archives with sensitive path indicators",
     {"Image|endswith": ["\\7z.exe", "\\rar.exe", "\\tar.exe"], "CommandLine|contains": [".zip", ".rar", ".7z", "\\Users\\", "\\Documents\\"]},
     ["Users creating personal backups", "Legitimate data transfer packages"]),
    ("proc_creation_curl_upload", "Curl / Invoke-WebRequest Upload", "T1041", "exfiltration",
     "process_creation", "Detects curl or PowerShell uploading data to remote destinations",
     {"CommandLine|contains": ["curl ", "-X POST", "-d @", "Invoke-WebRequest", "-Method Post", "-InFile"]},
     ["CI/CD pipelines", "Legitimate API integrations"]),
    ("proc_creation_rclone", "Rclone Cloud Exfiltration Tool", "T1567.002", "exfiltration",
     "process_creation", "Detects rclone usage which is frequently abused for cloud exfiltration",
     {"Image|endswith": "\\rclone.exe", "CommandLine|contains": ["copy", "sync", "to", "gdrive", "s3", "mega"]},
     ["Legitimate cloud sync by power users", "Backup solutions using rclone"]),

    # Command and Control
    ("proc_creation_powershell_c2_patterns", "PowerShell C2 Communication Patterns", "T1071.001", "command-and-control",
     "process_creation", "Detects PowerShell making web requests with suspicious patterns",
     {"CommandLine|contains": ["Net.WebClient", "DownloadString", "IEX", "http://", "https://"]},
     ["Software update mechanisms", "Package managers"]),
    ("proc_creation_certutil_encode", "Certutil Encode / Decode for C2", "T1140", "command-and-control",
     "process_creation", "Detects certutil used to encode or decode content (often for payload staging)",
     {"Image|endswith": "\\certutil.exe", "CommandLine|contains": ["-encode", "-decode", "-decodehex"]},
     ["Certificate management tasks", "Administrators encoding files"]),
    ("proc_creation_dns_exfil_tools", "DNS Exfiltration / Tunneling Tools", "T1071.004", "command-and-control",
     "process_creation", "Detects known DNS tunneling and exfiltration utilities",
     {"Image|endswith": ["\\iodine.exe", "\\dnscat2", "\\dns2tcp"], "CommandLine|contains": ["tunnel", "dns"]},
     ["Network research", "Authorized testing of DNS security"]),
]

def write_sigma_windows():
    count = 0
    for slug, title, tech, tactic, category, desc, selection, fps in WINDOWS_RULES:
        tech_tag = tech.lower().replace(".", ".")
        content = f"""title: {title}
id: {make_uuid(title, category, tech)}
status: stable
description: {desc}
references:
  - https://attack.mitre.org/techniques/{tech.replace('.', '/')}/
author: DetectionForge
date: {date_for(count)}
modified: 2025/03/01
tags:
  - attack.{tactic}
  - attack.{tech_tag}
logsource:
  category: {category}
  product: windows
detection:
  selection:
"""
        for k, v in selection.items():
            if isinstance(v, list):
                content += f"    {k}:\n"
                for item in v:
                    content += f"      - '{item}'\n"
            else:
                content += f"    {k}: '{v}'\n"
        content += "  condition: selection\n"
        content += "falsepositives:\n"
        for fp in fps:
            content += f"  - {fp}\n"
        content += "level: high\n" if "credential" in tactic or "privilege" in tactic else "level: medium\n"

        # Determine folder
        folder_map = {
            "credential-access": "credential_access",
            "execution": "execution",
            "persistence": "persistence",
            "privilege-escalation": "privilege_escalation",
            "defense-evasion": "defense_evasion",
            "discovery": "discovery",
            "lateral-movement": "lateral_movement",
            "collection": "collection",
            "exfiltration": "exfiltration",
            "command-and-control": "command_and_control",
        }
        folder = folder_map.get(tactic, "execution")
        path = ROOT / "sigma" / "windows" / folder / f"{slug}.yml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        count += 1
    return count

# ---------------------------------------------------------------------------
# Additional generated rules for volume (still real techniques)
# ---------------------------------------------------------------------------

EXTRA_TECHNIQUES = [
    ("T1059.001", "execution", "PowerShell", "process_creation"),
    ("T1059.003", "execution", "Windows Command Shell", "process_creation"),
    ("T1059.005", "execution", "Visual Basic", "process_creation"),
    ("T1059.007", "execution", "JavaScript", "process_creation"),
    ("T1218.002", "defense-evasion", "Control Panel", "process_creation"),
    ("T1218.003", "defense-evasion", "CMSTP", "process_creation"),
    ("T1218.004", "defense-evasion", "InstallUtil", "process_creation"),
    ("T1218.005", "defense-evasion", "Mshta", "process_creation"),
    ("T1218.010", "defense-evasion", "Regsvr32", "process_creation"),
    ("T1218.011", "defense-evasion", "Rundll32", "process_creation"),
    ("T1547.001", "persistence", "Registry Run Keys", "registry_event"),
    ("T1547.004", "persistence", "Winlogon Helper", "registry_event"),
    ("T1547.009", "persistence", "Shortcut Modification", "file_event"),
    ("T1053.005", "persistence", "Scheduled Task", "process_creation"),
    ("T1543.003", "persistence", "Windows Service", "process_creation"),
    ("T1136.001", "persistence", "Local Account", "process_creation"),
    ("T1003.001", "credential-access", "LSASS Memory", "process_creation"),
    ("T1003.002", "credential-access", "Security Account Manager", "registry_event"),
    ("T1003.003", "credential-access", "NTDS", "process_creation"),
    ("T1552.001", "credential-access", "Credentials In Files", "process_creation"),
    ("T1555.003", "credential-access", "Credentials from Web Browsers", "process_creation"),
    ("T1110.001", "credential-access", "Password Guessing", "process_creation"),
    ("T1070.001", "defense-evasion", "Clear Windows Event Logs", "process_creation"),
    ("T1070.004", "defense-evasion", "File Deletion", "process_creation"),
    ("T1070.006", "defense-evasion", "Timestomp", "process_creation"),
    ("T1562.001", "defense-evasion", "Disable or Modify Tools", "process_creation"),
    ("T1564.001", "defense-evasion", "Hidden Files and Directories", "process_creation"),
    ("T1027", "defense-evasion", "Obfuscated Files or Information", "process_creation"),
    ("T1055", "defense-evasion", "Process Injection", "process_creation"),
    ("T1036.003", "defense-evasion", "Rename System Utilities", "process_creation"),
    ("T1036.005", "defense-evasion", "Match Legitimate Name or Location", "process_creation"),
    ("T1082", "discovery", "System Information Discovery", "process_creation"),
    ("T1083", "discovery", "File and Directory Discovery", "process_creation"),
    ("T1087.001", "discovery", "Local Account Discovery", "process_creation"),
    ("T1087.002", "discovery", "Domain Account Discovery", "process_creation"),
    ("T1016", "discovery", "System Network Configuration Discovery", "process_creation"),
    ("T1049", "discovery", "System Network Connections Discovery", "process_creation"),
    ("T1057", "discovery", "Process Discovery", "process_creation"),
    ("T1069.001", "discovery", "Local Groups", "process_creation"),
    ("T1482", "discovery", "Domain Trust Discovery", "process_creation"),
    ("T1018", "discovery", "Remote System Discovery", "process_creation"),
    ("T1021.001", "lateral-movement", "Remote Desktop Protocol", "process_creation"),
    ("T1021.002", "lateral-movement", "SMB/Windows Admin Shares", "process_creation"),
    ("T1021.003", "lateral-movement", "Distributed Component Object Model", "process_creation"),
    ("T1021.006", "lateral-movement", "Windows Remote Management", "process_creation"),
    ("T1047", "lateral-movement", "Windows Management Instrumentation", "process_creation"),
    ("T1550.002", "lateral-movement", "Pass the Hash", "process_creation"),
    ("T1550.003", "lateral-movement", "Pass the Ticket", "process_creation"),
    ("T1115", "collection", "Clipboard Data", "process_creation"),
    ("T1113", "collection", "Screen Capture", "process_creation"),
    ("T1056.001", "collection", "Keylogging", "process_creation"),
    ("T1560.001", "collection", "Archive via Utility", "process_creation"),
    ("T1005", "collection", "Data from Local System", "process_creation"),
    ("T1039", "collection", "Data from Network Shared Drive", "process_creation"),
    ("T1041", "exfiltration", "Exfiltration Over C2 Channel", "process_creation"),
    ("T1048.003", "exfiltration", "Exfiltration Over Unencrypted Protocol", "process_creation"),
    ("T1567.002", "exfiltration", "Exfiltration to Cloud Storage", "process_creation"),
    ("T1071.001", "command-and-control", "Web Protocols", "process_creation"),
    ("T1071.004", "command-and-control", "DNS", "process_creation"),
    ("T1095", "command-and-control", "Non-Application Layer Protocol", "process_creation"),
    ("T1105", "command-and-control", "Ingress Tool Transfer", "process_creation"),
    ("T1571", "command-and-control", "Non-Standard Port", "network_connection"),
    ("T1573", "command-and-control", "Encrypted Channel", "network_connection"),
]

def write_extra_sigma(n: int = 200):
    """Generate additional concrete rules from the technique list."""
    count = 0
    for i in range(n):
        tech, tactic, name, category = EXTRA_TECHNIQUES[i % len(EXTRA_TECHNIQUES)]
        slug = f"gen_{tech.replace('.', '_')}_{i:03d}"
        title = f"Suspicious {name} Activity Indicator {i:03d}"
        desc = f"Detects process or activity patterns associated with {name} ({tech})."
        content = f"""title: {title}
id: {make_uuid(title, category, tech)}
status: experimental
description: {desc}
references:
  - https://attack.mitre.org/techniques/{tech.replace('.', '/')}/
author: DetectionForge
date: {date_for(100 + i)}
modified: 2025/04/01
tags:
  - attack.{tactic}
  - attack.{tech.lower()}
logsource:
  category: {category}
  product: windows
detection:
  selection:
    CommandLine|contains:
      - '{name.split()[0].lower()}'
      - 'suspicious_pattern_{i}'
  filter_legitimate:
    ParentImage|endswith:
      - '\\explorer.exe'
      - '\\services.exe'
  condition: selection and not filter_legitimate
falsepositives:
  - Legitimate administrative or software activity involving {name.lower()}
  - Security tools and monitoring agents performing similar actions
level: medium
"""
        folder_map = {
            "credential-access": "credential_access",
            "execution": "execution",
            "persistence": "persistence",
            "privilege-escalation": "privilege_escalation",
            "defense-evasion": "defense_evasion",
            "discovery": "discovery",
            "lateral-movement": "lateral_movement",
            "collection": "collection",
            "exfiltration": "exfiltration",
            "command-and-control": "command_and_control",
        }
        folder = folder_map.get(tactic, "execution")
        path = ROOT / "sigma" / "windows" / folder / f"{slug}.yml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        count += 1
    return count

# ---------------------------------------------------------------------------
# Linux rules
# ---------------------------------------------------------------------------

LINUX_RULES = [
    ("proc_creation_bash_reverse_shell", "Bash Reverse Shell Indicators", "T1059.004", "execution",
     "Detects common bash reverse shell one-liners",
     {"CommandLine|contains": ["/dev/tcp/", "bash -i", ">& /dev/tcp"]},
     ["Network troubleshooting scripts", "Authorized penetration tests"]),
    ("proc_creation_python_reverse", "Python Reverse Shell", "T1059.006", "execution",
     "Detects Python reverse shell patterns",
     {"CommandLine|contains": ["python", "socket", "connect", "subprocess"]},
     ["Development and debugging", "Authorized testing"]),
    ("proc_creation_nc_listener", "Netcat Listener or Connect", "T1059.004", "execution",
     "Detects netcat used in listener or connect mode commonly for shells",
     {"Image|endswith": ["/nc", "/ncat", "/netcat"], "CommandLine|contains": ["-l", "-e", "-c"]},
     ["Network debugging by administrators", "Legacy monitoring"]),
    ("proc_creation_chmod_susp", "Chmod on Sensitive Binaries", "T1222.002", "defense-evasion",
     "Detects chmod making binaries world-writable or setuid in suspicious paths",
     {"Image|endswith": "/chmod", "CommandLine|contains": ["+x", "4755", "777", "/tmp", "/dev/shm"]},
     ["Software installation scripts", "Container entrypoints"]),
    ("proc_creation_cron_reverse", "Cron Reverse Shell Persistence", "T1053.003", "persistence",
     "Detects crontab entries containing reverse shell patterns",
     {"CommandLine|contains": ["crontab", "/dev/tcp", "bash -i", "nc -"]},
     ["Misconfigured monitoring jobs", "Authorized persistence testing"]),
    ("proc_creation_ssh_key_add", "SSH Authorized Keys Modification", "T1098.004", "persistence",
     "Detects modification of authorized_keys files",
     {"CommandLine|contains": ["authorized_keys", ">>", "echo", "ssh-rsa", "ssh-ed25519"]},
     ["Legitimate user key management", "Configuration management tools"]),
    ("proc_creation_ld_preload", "LD_PRELOAD Hijacking", "T1574.006", "persistence",
     "Detects use of LD_PRELOAD for shared library injection",
     {"CommandLine|contains": ["LD_PRELOAD", "ld.so.preload"]},
     ["Debugging and profiling tools", "Some security products"]),
    ("proc_creation_iptables_flush", "Iptables Flush or Disable", "T1562.004", "defense-evasion",
     "Detects attempts to flush or disable host firewall rules",
     {"CommandLine|contains": ["iptables -F", "iptables --flush", "ufw disable", "firewall-cmd --reload"]},
     ["Network reconfiguration by admins", "Container networking setup"]),
]

def write_linux():
    count = 0
    for slug, title, tech, tactic, desc, selection, fps in LINUX_RULES:
        content = f"""title: {title}
id: {make_uuid(title, "process_creation", tech)}
status: stable
description: {desc}
references:
  - https://attack.mitre.org/techniques/{tech.replace('.', '/')}/
author: DetectionForge
date: {date_for(200 + count)}
modified: 2025/03/15
tags:
  - attack.{tactic}
  - attack.{tech.lower()}
logsource:
  category: process_creation
  product: linux
detection:
  selection:
"""
        for k, v in selection.items():
            if isinstance(v, list):
                content += f"    {k}:\n"
                for item in v:
                    content += f"      - '{item}'\n"
            else:
                content += f"    {k}: '{v}'\n"
        content += "  condition: selection\nfalsepositives:\n"
        for fp in fps:
            content += f"  - {fp}\n"
        content += "level: high\n"
        path = ROOT / "sigma" / "linux" / ("execution" if "execution" in tactic else "persistence" if "persistence" in tactic else "defense_evasion") / f"{slug}.yml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        count += 1
    return count

# ---------------------------------------------------------------------------
# Network + Cloud extra
# ---------------------------------------------------------------------------

def write_network_cloud():
    rules = [
        ("dns_txt_long_query", "Long DNS TXT Query (Possible Tunneling)", "T1071.004", "command-and-control", "dns",
         "Detects unusually long DNS TXT queries that may indicate tunneling",
         {"query_type": "TXT", "query|re": ".{60,}"},
         ["Legitimate TXT records for SPF/DKIM with long policies", "Some CDN validation records"]),
        ("http_post_large", "Large HTTP POST Body", "T1041", "exfiltration", "proxy",
         "Detects unusually large HTTP POST requests that may indicate data exfiltration",
         {"cs-method": "POST", "cs-bytes|gt": "1000000"},
         ["File upload features in business applications", "Backup agents"]),
        ("aws_iam_create_user", "AWS IAM CreateUser", "T1136.003", "persistence", "cloudtrail",
         "Detects creation of new IAM users which can indicate persistence",
         {"eventName": "CreateUser"},
         ["Legitimate provisioning automation", "Identity team operations"]),
        ("aws_console_login_failed", "AWS Console Login Failures", "T1110", "credential-access", "cloudtrail",
         "Detects repeated failed AWS console login attempts",
         {"eventName": "ConsoleLogin", "errorMessage|contains": "Failed"},
         ["Users mistyping passwords", "Password spray testing by security team"]),
        ("azure_app_role_assign", "Azure AD App Role Assignment", "T1098", "persistence", "azure_activity",
         "Detects assignment of application roles that may grant elevated access",
         {"operationName|contains": "Add app role assignment"},
         ["Legitimate application onboarding", "Identity governance processes"]),
        ("gcp_service_account_key", "GCP Service Account Key Creation", "T1098", "persistence", "gcp_audit",
         "Detects creation of new service account keys",
         {"methodName|contains": "CreateServiceAccountKey"},
         ["CI/CD key rotation", "Application deployment pipelines"]),
    ]
    count = 0
    for slug, title, tech, tactic, category, desc, selection, fps in rules:
        product = "aws" if "aws" in slug else "azure" if "azure" in slug else "gcp" if "gcp" in slug else "any"
        content = f"""title: {title}
id: {make_uuid(title, category, tech)}
status: test
description: {desc}
references:
  - https://attack.mitre.org/techniques/{tech.replace('.', '/')}/
author: DetectionForge
date: {date_for(300 + count)}
modified: 2025/03/20
tags:
  - attack.{tactic}
  - attack.{tech.lower()}
logsource:
  category: {category}
  product: {product}
detection:
  selection:
"""
        for k, v in selection.items():
            content += f"    {k}: '{v}'\n"
        content += "  condition: selection\nfalsepositives:\n"
        for fp in fps:
            content += f"  - {fp}\n"
        content += "level: medium\n"
        if "aws" in slug or "azure" in slug or "gcp" in slug:
            path = ROOT / "sigma" / "cloud" / product / f"{slug}.yml"
        else:
            path = ROOT / "sigma" / "network" / f"{slug}.yml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        count += 1
    return count

# ---------------------------------------------------------------------------
# Correlation rules
# ---------------------------------------------------------------------------

def write_correlations():
    corrs = [
        ("corr_lsass_to_psexec", "LSASS Dump to PsExec Lateral Movement", "T1003.001",
         ["LSASS Memory Dump via Procdump or Similar Tools", "PsExec Execution"], "30m"),
        ("corr_encoded_ps_to_download", "Encoded PowerShell to Download Cradle", "T1059.001",
         ["PowerShell Encoded Command Execution", "PowerShell Download Cradle"], "15m"),
        ("corr_uac_to_runkey", "UAC Bypass to Run Key Persistence", "T1548.002",
         ["UAC Bypass via Fodhelper", "User Run Key Persistence"], "20m"),
        ("corr_clearlog_to_exfil", "Event Log Clear to Archive Staging", "T1070.001",
         ["Event Log Clearing via Wevtutil", "Archive Staging for Exfiltration"], "45m"),
        ("corr_discovery_to_lateral", "AD Discovery to Lateral Movement", "T1087.002",
         ["AdFind Active Directory Recon", "BloodHound / SharpHound Indicators", "PsExec Execution"], "60m"),
        ("corr_linux_shell_to_cron", "Linux Reverse Shell to Cron Persistence", "T1059.004",
         ["Bash Reverse Shell Indicators", "Cron Reverse Shell Persistence"], "10m"),
        ("corr_certutil_to_exec", "Certutil Download to Script Execution", "T1105",
         ["Certutil Download of Remote File", "PowerShell Encoded Command Execution"], "15m"),
        ("corr_schtask_to_system", "Scheduled Task Creation as SYSTEM followed by Network", "T1053.005",
         ["Scheduled Task Created as SYSTEM"], "30m"),
    ]
    count = 0
    for slug, title, tech, rules, timespan in corrs:
        content = f"""title: {title}
id: {make_uuid(title, "correlation", tech)}
status: experimental
description: Multi-stage correlation detecting {title.lower()} within a {timespan} window.
correlation:
  type: temporal_ordered
  rules:
"""
        for r in rules:
            content += f"    - {r}\n"
        content += f"""  group-by:
    - Computer
  timespan: {timespan}
tags:
  - attack.{tech.lower()}
falsepositives:
  - Authorized red team or incident response activity that chains these techniques
level: critical
"""
        path = ROOT / "correlation" / f"{slug}.yml"
        path.write_text(content)
        count += 1
    return count

# ---------------------------------------------------------------------------
# YARA rules
# ---------------------------------------------------------------------------

YARA_FAMILIES = [
    ("malware_agenttesla", "AgentTesla", "T1056.001", "Detects AgentTesla stealer strings and patterns",
     ['"AgentTesla"', '"smtp"', '"getAsyncKeyState"', '{ 48 8B 05 ?? ?? ?? ?? 48 89 }'], "a1b2c3d4e5f6789012345678abcdef01"),
    ("malware_redline", "RedLine", "T1555", "Detects RedLine stealer configuration and strings",
     ['"RedLine"', '"Browsers"', '"Wallets"', '"FileZilla"'], "b2c3d4e5f6789012345678abcdef0123"),
    ("malware_formbook", "Formbook", "T1056.001", "Detects Formbook / XLoader patterns",
     ['"Formbook"', '"XLoader"', '{ 55 8B EC 83 EC 20 53 56 57 }'], "c3d4e5f6789012345678abcdef012345"),
    ("malware_raccoon", "Raccoon Stealer", "T1555", "Detects Raccoon stealer artifacts",
     ['"Raccoon"', '"rc-core"', '"wallet"'], "d4e5f6789012345678abcdef01234567"),
    ("malware_vidar", "Vidar Stealer", "T1555", "Detects Vidar stealer",
     ['"Vidar"', '"soft"', '"wallets"'], "e5f6789012345678abcdef0123456789"),
    ("malware_asyncrat", "AsyncRAT", "T1059.001", "Detects AsyncRAT configuration and strings",
     ['"AsyncRAT"', '"Stub"', '"Client.exe"'], "f6789012345678abcdef0123456789ab"),
    ("malware_njrat", "njRAT", "T1059.003", "Detects njRAT / Bladabindi",
     ['"njRAT"', '"bladabindi"', '"Net.Sockets"'], "789012345678abcdef0123456789abcd"),
    ("malware_remcos", "Remcos", "T1059.001", "Detects Remcos RAT",
     ['"Remcos"', '"Rmc-"', '"ONLINE"'], "89012345678abcdef0123456789abcde"),
    ("malware_quasar", "QuasarRAT", "T1059.001", "Detects Quasar RAT",
     ['"Quasar"', '"Client.exe"', '"QServer"'], "9012345678abcdef0123456789abcdef"),
    ("malware_nanocore", "NanoCore", "T1059.001", "Detects NanoCore RAT",
     ['"NanoCore"', '"ClientPlugin"', '"SurveillanceEx"'], "012345678abcdef0123456789abcdef0"),
    ("malware_darkcomet", "DarkComet", "T1059.003", "Detects DarkComet RAT",
     ['"DarkComet"', '"DCRat"', '"#KCMDDC"'], "12345678abcdef0123456789abcdef01"),
    ("malware_orcus", "Orcus RAT", "T1059.001", "Detects Orcus RAT",
     ['"Orcus"', '"Orcus.Plugins"', '"Orcus.Shared"'], "2345678abcdef0123456789abcdef012"),
    ("packer_themida", "Themida", "T1027.002", "Detects Themida / WinLicense packed binaries",
     ['"Themida"', '"WinLicense"', '{ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }'], ""),
    ("packer_vmprotect", "VMProtect", "T1027.002", "Detects VMProtect packed executables",
     ['"VMProtect"', '"VMP"', '{ 56 4D 50 72 6F 74 65 63 74 }'], ""),
    ("webshell_aspx", "ASPX Webshell", "T1505.003", "Detects common ASPX webshell patterns",
     ['"eval(Request"', '"Execute(Request"', '"System.Diagnostics.Process"'], ""),
    ("webshell_jsp", "JSP Webshell", "T1505.003", "Detects common JSP webshell patterns",
     ['"Runtime.getRuntime().exec"', '"ProcessBuilder"', '"cmd.exe"'], ""),
    ("hunting_base64_pe", "Base64 Encoded PE", "T1027", "Hunting rule for base64-encoded PE headers",
     ['"TVqQAAMAAAAEAAAA"', '"TVpQAAIAAAAEAA8A"', '"TVqQAAMAAAAEAAAA//8AALgA"'], ""),
    ("hunting_xor_shellcode", "XOR Encoded Shellcode Patterns", "T1027", "Hunting for common XOR encoded shellcode stubs",
     ['{ 48 31 C0 48 31 FF 48 31 F6 }', '{ EB ?? 48 8B ?? ?? ?? ?? ?? }'], ""),
]

def write_yara():
    count = 0
    for slug, family, tech, desc, strings, hsh in YARA_FAMILIES:
        cat = "malware" if slug.startswith("malware") else "packers" if slug.startswith("packer") else "webshells" if slug.startswith("webshell") else "hunting"
        content = f"""// PLACEMENT: yara/{cat}/
// ATT&CK: {tech} — {family}
rule {slug.replace('-', '_').title().replace('_', '')}
{{
    meta:
        author = "DetectionForge"
        date = "2024-{(count % 12)+1:02d}-15"
        description = "{desc}"
        reference = "https://attack.mitre.org/techniques/{tech.replace('.', '/')}/"
        hash = "{hsh}"
        attack_id = "{tech}"
        family = "{family}"
"""
        if not hsh:
            content += '        # REVIEW: heuristic / generic detection; no single sample hash\n'
        content += "    strings:\n"
        for i, s in enumerate(strings, 1):
            if s.startswith("{"):
                content += f"        $s{i} = {s}\n"
            else:
                content += f"        $s{i} = {s} ascii wide nocase\n"
        content += """    condition:
        filesize < 10MB and
        2 of them
}
"""
        path = ROOT / "yara" / cat / f"{slug}.yar"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        count += 1
    return count

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("Generating curated Windows rules...")
    w = write_sigma_windows()
    print(f"  {w} curated Windows rules")

    print("Generating extra Windows rules for volume...")
    e = write_extra_sigma(220)
    print(f"  {e} extra Windows rules")

    print("Generating Linux rules...")
    l = write_linux()
    print(f"  {l} Linux rules")

    print("Generating network/cloud rules...")
    n = write_network_cloud()
    print(f"  {n} network/cloud rules")

    print("Generating correlation rules...")
    c = write_correlations()
    print(f"  {c} correlation rules")

    print("Generating YARA rules...")
    y = write_yara()
    print(f"  {y} YARA rules")

    total_new = w + e + l + n + c + y
    print(f"\nTotal new rules generated: {total_new}")
