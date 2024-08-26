rule JAR_STRRAT_April_2024 {
    meta:
        author = "NDA0E"
        date = "2024-04-28"
        description = "Detects STRRAT config filename"
        yarahub_uuid = "bd70fcd9-5849-4a3b-80d6-76418dd2bd33"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "5d16505a5abfcfc99095a676f1f0bd64"
        malpedia_family = "jar.strrat"
    strings:
        $jar_file = "META-INF/MANIFEST.MF" ascii
        $config = "config.txt" ascii
    condition:
        all of them
}