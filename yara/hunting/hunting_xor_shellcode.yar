// PLACEMENT: yara/hunting/
// ATT&CK: T1027 — XOR Encoded Shellcode Patterns
rule HuntingXorShellcode
{
    meta:
        author = "DetectionForge"
        date = "2024-06-15"
        description = "Hunting for common XOR encoded shellcode stubs"
        reference = "https://attack.mitre.org/techniques/T1027/"
        hash = ""
        attack_id = "T1027"
        family = "XOR Encoded Shellcode Patterns"
        # REVIEW: heuristic / generic detection; no single sample hash
    strings:
        $s1 = { 48 31 C0 48 31 FF 48 31 F6 }
        $s2 = { EB ?? 48 8B ?? ?? ?? ?? ?? }
    condition:
        filesize < 10MB and
        2 of them
}
