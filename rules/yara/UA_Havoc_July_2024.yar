rule UA_Havoc_July_2024 {
    meta:
        author = "NDA0E"
        date = "2024-07-11"
        description = "Detects Havoc based on User Agent"
        yarahub_uuid = "8fd8c582-ced3-4a3d-b758-9b601892c642"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "69b4e52a3f1373a1f76d91d23aeddcce"
        malpedia_family = "win.havoc"
    strings:
        $ua = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36" wide ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}