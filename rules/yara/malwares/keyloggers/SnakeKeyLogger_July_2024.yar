rule SnakeKeyLogger_July_2024 {
    meta:
        author = "NDA0E"
        date = "2024-07-11"
        description = "Detects SnakeKeyLogger payload"
        yarahub_uuid = "dd01b8f5-ba53-4bbe-8b26-e8beacbca9c8"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "6f6bbf610dddc0759b605d4ac9f25fbe"
        malpedia_family = "win.404keylogger"
    strings:
        $SnakeKeylogger = "\\SnakeKeylogger\\" wide ascii
        $SnakeTracker = "| Snake Tracker" wide ascii
        $FoundFrom = "Found From:" wide ascii
    condition:
        uint16(0) == 0x5a4d and any of them and filesize < 1MB
}