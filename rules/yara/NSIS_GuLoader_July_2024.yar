rule NSIS_GuLoader_July_2024 {
    meta:
        author = "NDA0E"
        date = "2024-07-10"
        description = "Detects GuLoader packed with NSIS installer"
        yarahub_uuid = "f47c7191-45e1-4d58-96e8-56e47226a537"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "b409d2fd594633bc71e64da08aed9951"
        malpedia_family = "win.cloudeye"
    strings:
        $NSIS_Error = "NSIS_Error" wide ascii
        $CRYPTBASE = "CRYPTBASE" ascii
        $iexplorer = "Microsoft\\Internet Explorer\\Quick Launch" wide ascii
        $Rename = "[Rename]" ascii
        $garbage = "%s=%s" ascii
    condition:
        uint16(0) == 0x5a4d and all of them and filesize > 480KB and filesize < 1MB
}
