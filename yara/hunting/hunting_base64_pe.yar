// PLACEMENT: yara/hunting/
// ATT&CK: T1027 — Base64 Encoded PE
rule HuntingBase64Pe
{
    meta:
        author = "DetectionForge"
        date = "2024-05-15"
        description = "Hunting rule for base64-encoded PE headers"
        reference = "https://attack.mitre.org/techniques/T1027/"
        hash = ""
        attack_id = "T1027"
        family = "Base64 Encoded PE"
        # REVIEW: heuristic / generic detection; no single sample hash
    strings:
        $s1 = "TVqQAAMAAAAEAAAA" ascii wide nocase
        $s2 = "TVpQAAIAAAAEAA8A" ascii wide nocase
        $s3 = "TVqQAAMAAAAEAAAA//8AALgA" ascii wide nocase
    condition:
        filesize < 10MB and
        2 of them
}
