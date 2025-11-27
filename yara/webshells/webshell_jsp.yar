// PLACEMENT: yara/webshells/
// ATT&CK: T1505.003 — JSP Webshell
rule WebshellJsp
{
    meta:
        author = "DetectionForge"
        date = "2024-04-15"
        description = "Detects common JSP webshell patterns"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
        hash = ""
        attack_id = "T1505.003"
        family = "JSP Webshell"
        # REVIEW: heuristic / generic detection; no single sample hash
    strings:
        $s1 = "Runtime.getRuntime().exec" ascii wide nocase
        $s2 = "ProcessBuilder" ascii wide nocase
        $s3 = "cmd.exe" ascii wide nocase
    condition:
        filesize < 10MB and
        2 of them
}
