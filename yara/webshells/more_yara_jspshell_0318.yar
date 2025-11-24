// PLACEMENT: yara/webshells/
rule More_JSPShell_0318
{
    meta:
        author = "DetectionForge"
        date = "2024-10-01"
        description = "Volume YARA for JSPShell"
        reference = "https://attack.mitre.org/"
        hash = ""
        attack_id = "T1059.001"
        family = "JSPShell"
        # REVIEW: volume
    strings:
        $s1 = "JSPShell" ascii wide nocase
        $s2 = "more_yara_318" ascii
    condition:
        filesize < 10MB and 1 of them
}
