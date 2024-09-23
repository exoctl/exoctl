rule EXE_VenomRAT_May_2024 {
    meta:
        author = "NDA0E"
        date = "2024-05-23"
        description = "Detects VenomRAT"
        yarahub_uuid = "47d5831b-c450-46f5-aa04-19cb0a47843c"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "7ac0adf482250172280defec7a7054da"
        malpedia_family = "win.venom"
    strings:
        $VenomRATByVenom = "VenomRATByVenom" wide ascii
        $OfflineKeylogger = "OfflineKeylogger" wide ascii
        $Paste_bin = "Paste_bin" wide ascii
        $Anti_virus = "Anti_virus" wide ascii
        $OfflineKeylog = "OfflineKeylog sending" wide ascii
        $keylogsetting = "keylogsetting" wide ascii
        $keyLogger = "keyLogger" wide ascii
        $DataLogs_keylog_online = "DataLogs_keylog_online.txt" wide ascii
        $DataLogs_keylog_offline = "DataLogs_keylog_offline.txt" wide ascii
        $KeylogConfFile = "KeylogConfFile" ascii
        $amsi_dll = "YW1zaS5kbGw=" wide ascii
    condition:
        ($VenomRATByVenom or 4 of them) and uint16(0) == 0x5a4d
}