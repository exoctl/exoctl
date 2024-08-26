rule ShellScript_Downloader {
    meta:
        author = "NDA0E"
        date = "2024-07-14"
        description = "Detects Generic ShellScript Downloader"
        yarahub_uuid = "a41413f4-bbec-4952-8010-57d0e869dbf7"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "95cde598a6595a248fdf56d674a5dc79"  
    strings:
        $wget = /wget\s+(http|https):\/\//
        $curl = /curl\s+(http|https):\/\//
        $chmod = /chmod\s+\+x/
    condition:
	($wget or $curl) and $chmod
}