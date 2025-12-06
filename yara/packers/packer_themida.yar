// PLACEMENT: yara/packers/
// ATT&CK: T1027.002 — Themida
rule PackerThemida
{
    meta:
        author = "DetectionForge"
        date = "2024-01-15"
        description = "Detects Themida / WinLicense packed binaries"
        reference = "https://attack.mitre.org/techniques/T1027/002/"
        hash = ""
        attack_id = "T1027.002"
        family = "Themida"
        # REVIEW: heuristic / generic detection; no single sample hash
    strings:
        $s1 = "Themida" ascii wide nocase
        $s2 = "WinLicense" ascii wide nocase
        $s3 = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        filesize < 10MB and
        2 of them
}
