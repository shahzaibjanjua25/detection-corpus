// PLACEMENT: yara/packers/
// ATT&CK: T1027.002 — Obfuscated Files or Information: Software Packing
rule Packer_UPX
{
    meta:
        author = "DetectionForge"
        date = "2024-04-01"
        description = "Detects UPX packed executables"
        reference = "https://upx.github.io/"
        hash = ""
        attack_id = "T1027.002"
        family = "UPX"
        # REVIEW: generic packer detection; no single sample hash
    strings:
        $s1 = "UPX!" ascii
        $s2 = "UPX0" ascii
        $s3 = "UPX1" ascii
        $s4 = { 55 50 58 21 }
    condition:
        uint16(0) == 0x5A4D and
        2 of them
}
