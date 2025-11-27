// PLACEMENT: yara/webshells/
// ATT&CK: T1505.003 — Server Software Component: Web Shell
rule Webshell_PHP_Generic
{
    meta:
        author = "DetectionForge"
        date = "2024-08-15"
        description = "Detects common PHP webshell patterns including eval, system, and base64 decode constructs"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
        hash = ""
        attack_id = "T1505.003"
        family = "PHP_Webshell"
        # REVIEW: heuristic webshell detection; no single hash
    strings:
        $s1 = "eval($_POST" ascii nocase
        $s2 = "eval($_GET" ascii nocase
        $s3 = "system($_" ascii nocase
        $s4 = "base64_decode($" ascii nocase
        $s5 = "shell_exec($" ascii nocase
        $s6 = "passthru($" ascii nocase
    condition:
        filesize < 100KB and
        2 of them
}
