// PLACEMENT: yara/webshells/
rule More_PHPShell_0337
{
    meta:
        author = "DetectionForge"
        date = "2024-10-01"
        description = "Volume YARA for PHPShell"
        reference = "https://attack.mitre.org/"
        hash = ""
        attack_id = "T1059.001"
        family = "PHPShell"
        # REVIEW: volume
    strings:
        $s1 = "PHPShell" ascii wide nocase
        $s2 = "more_yara_337" ascii
    condition:
        filesize < 10MB and 1 of them
}
