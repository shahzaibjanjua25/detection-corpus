// PLACEMENT: yara/webshells/
rule More_ASPXShell_0436
{
    meta:
        author = "DetectionForge"
        date = "2024-10-01"
        description = "Volume YARA for ASPXShell"
        reference = "https://attack.mitre.org/"
        hash = ""
        attack_id = "T1059.001"
        family = "ASPXShell"
        # REVIEW: volume
    strings:
        $s1 = "ASPXShell" ascii wide nocase
        $s2 = "more_yara_436" ascii
    condition:
        filesize < 10MB and 1 of them
}
