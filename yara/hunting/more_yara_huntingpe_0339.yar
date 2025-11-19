// PLACEMENT: yara/hunting/
rule More_HuntingPE_0339
{
    meta:
        author = "DetectionForge"
        date = "2024-10-01"
        description = "Volume YARA for HuntingPE"
        reference = "https://attack.mitre.org/"
        hash = ""
        attack_id = "T1059.001"
        family = "HuntingPE"
        # REVIEW: volume
    strings:
        $s1 = "HuntingPE" ascii wide nocase
        $s2 = "more_yara_339" ascii
    condition:
        filesize < 10MB and 1 of them
}
