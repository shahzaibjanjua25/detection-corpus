// PLACEMENT: yara/packers/
rule More_UPX_0414
{
    meta:
        author = "DetectionForge"
        date = "2024-10-01"
        description = "Volume YARA for UPX"
        reference = "https://attack.mitre.org/"
        hash = ""
        attack_id = "T1059.001"
        family = "UPX"
        # REVIEW: volume
    strings:
        $s1 = "UPX" ascii wide nocase
        $s2 = "more_yara_414" ascii
    condition:
        filesize < 10MB and 1 of them
}
