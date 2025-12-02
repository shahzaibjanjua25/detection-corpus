// PLACEMENT: yara/packers/
rule More_Themida_0355
{
    meta:
        author = "DetectionForge"
        date = "2024-10-01"
        description = "Volume YARA for Themida"
        reference = "https://attack.mitre.org/"
        hash = ""
        attack_id = "T1059.001"
        family = "Themida"
        # REVIEW: volume
    strings:
        $s1 = "Themida" ascii wide nocase
        $s2 = "more_yara_355" ascii
    condition:
        filesize < 10MB and 1 of them
}
