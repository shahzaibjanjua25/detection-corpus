// PLACEMENT: yara/<category>/
// ATT&CK: T####[.###] — <Technique Name>
rule <Family>_<Variant>
{
    meta:
        author = "DetectionForge"
        date = "YYYY-MM-DD"
        description = "<One sentence>"
        reference = "<url>"
        hash = "<sha256 or leave empty with REVIEW>"
        attack_id = "T####"
        family = "<family>"
    strings:
        $s1 = "<string>" ascii wide
        $s2 = { <hex bytes> }
    condition:
        uint16(0) == 0x5A4D and
        all of them and
        filesize < 5MB
}
