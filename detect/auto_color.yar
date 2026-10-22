import "elf"

/*
 * Hardened Auto-Color detection rule.
 * Standalone, testable copy of DETECTION.md §6.
 *
 * Strategy: anchor on crypto/structural constants that are expensive for an
 * operator to change, and treat the swappable path strings as supporting
 * evidence rather than the primary signal.
 *
 * NOTE: the $k_const / $h_seed / $sdec byte patterns are the little-endian
 * encodings of the magic constants documented in SPECS.md. Verify the exact
 * instruction encoding against a real sample before production use; widen with
 * wildcards if your compiler reorders operands.
 */
rule AutoColor_Linux_Backdoor_v2 {
    meta:
        description = "Auto-Color Linux backdoor - structural + string detection"
        reference   = "SPECS.md; DETECTION.md; Unit 42 Auto-Color reporting"
        severity    = "critical"
        hash1 = "815b74947d3a78a1b7d2aece43596ddc0ffc264e26092f1f9b6409c62e1437d6"
        hash2 = "270fc72074c697ba5921f7b61a6128b968ca6ccbf8906645e796cfc3072d4c43"

    strings:
        // --- HARD: crypto constants (SPECS.md 4.2 / 5.1) ---
        $k_const = { 27 28 E5 70 }                      // 0x70E52827 LE (key update)
        $h_seed  = { 42 0B 7C CE }                      // 0xCE7C0B42 LE (path-hash seed)
        $sdec    = { 83 C0 7B 83 F0 1F 83 E8 7B }       // add 123; xor 0x1F; sub 123

        // --- SOFT: paths / names (cheap to change) ---
        $p1 = "/var/log/cross" ascii
        $p2 = "/tmp/cross" ascii
        $p3 = "/etc/ld.so.preload.xxx" ascii
        $p4 = "libcext.so.2" ascii
        $p5 = "config-err-" ascii
        $p6 = "/etc/ld.so.preload" ascii

    condition:
        uint32(0) == 0x464c457f and     // ELF magic \x7fELF
        filesize < 2MB and
        (
            (any of ($k_const, $h_seed, $sdec) and 2 of ($p*))
            or 4 of ($p*)
        )
}
