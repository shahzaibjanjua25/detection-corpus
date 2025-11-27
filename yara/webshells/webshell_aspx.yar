// PLACEMENT: yara/webshells/
// ATT&CK: T1505.003 — ASPX Webshell
rule WebshellAspx
{
    meta:
        author = "DetectionForge"
        date = "2024-03-15"
        description = "Detects common ASPX webshell patterns"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
        hash = ""
        attack_id = "T1505.003"
        family = "ASPX Webshell"
        # REVIEW: heuristic / generic detection; no single sample hash
    strings:
        $s1 = "eval(Request" ascii wide nocase
        $s2 = "Execute(Request" ascii wide nocase
        $s3 = "System.Diagnostics.Process" ascii wide nocase
    condition:
        filesize < 10MB and
        2 of them
}
