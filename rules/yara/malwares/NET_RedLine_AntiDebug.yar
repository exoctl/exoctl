rule NET_RedLine_AntiDebug {
    meta:
        author = "NDA0E"
        date = "2024-07-10"
        description = "Detects RedLine evading .NET debuggers"
        yarahub_uuid = "a3857c5f-e351-4165-a22f-80249d906ec1"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "dc41a996f5f11fe1599529446f3d494a"
        malpedia_family = "win.redline_stealer"
    strings:
        $browserPaths = "browserPaths" ascii
        $ClientCredentials = "ClientCredentials" ascii
        $de4dot = "de4dot" wide ascii
        $dnspy = "dnspy" wide ascii
    condition:
        uint16(0) == 0x5a4d and all of them and filesize < 1MB
}