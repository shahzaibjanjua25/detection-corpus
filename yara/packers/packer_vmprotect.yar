// PLACEMENT: yara/packers/
// ATT&CK: T1027.002 — VMProtect
rule PackerVmprotect
{
    meta:
        author = "DetectionForge"
        date = "2024-02-15"
        description = "Detects VMProtect packed executables"
        reference = "https://attack.mitre.org/techniques/T1027/002/"
        hash = ""
        attack_id = "T1027.002"
        family = "VMProtect"
        # REVIEW: heuristic / generic detection; no single sample hash
    strings:
        $s1 = "VMProtect" ascii wide nocase
        $s2 = "VMP" ascii wide nocase
        $s3 = { 56 4D 50 72 6F 74 65 63 74 }
    condition:
        filesize < 10MB and
        2 of them
}
