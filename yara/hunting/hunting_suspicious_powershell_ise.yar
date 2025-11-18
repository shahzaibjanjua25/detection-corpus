// PLACEMENT: yara/hunting/
// ATT&CK: T1059.001 — Command and Scripting Interpreter: PowerShell
rule Hunting_Suspicious_PowerShell_Artifacts
{
    meta:
        author = "DetectionForge"
        date = "2024-09-01"
        description = "Hunting rule for common malicious PowerShell constructs in scripts and memory dumps"
        reference = "https://attack.mitre.org/techniques/T1059/001/"
        hash = ""
        attack_id = "T1059.001"
        family = "PowerShell_Hunting"
        # REVIEW: hunting heuristic
    strings:
        $s1 = "FromBase64String" ascii wide
        $s2 = "DownloadString" ascii wide
        $s3 = "IEX (" ascii wide
        $s4 = "-EncodedCommand" ascii wide
        $s5 = "System.Reflection.Assembly" ascii wide
    condition:
        3 of them and
        filesize < 1MB
}
