rule EXE_Vidar_May_2024 {
    meta:
        author = "NDA0E"
        date = "2024-05-24"
        description = "Detects Vidar payload"
        yarahub_uuid = "b11d586b-eab8-4f37-8079-a7950acbd8b7"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "9aa31995984f17e944621d440c0e0823"
        malpedia_family = "win.vidar"
    strings:
        $targetpath = "SELECT target_path, tab_url from downloads" ascii
        $Monerowallet = "\\Monero\\wallet.keys" ascii
        $walletpath = "@wallet_path" ascii
        $monerocore = "SOFTWARE\\monero-project\\monero-core" ascii
        $steamtokens = "Soft\\Steam\\steam_tokens.txt" ascii
        $BraveWallet = "\\BraveWallet\\Preferences" ascii
        $Inmemory = "Work Dir: In memory" ascii
        $FileZilla = "Soft: FileZilla" ascii
        $GoogleAccounts = "GoogleAccounts" ascii
        $Stable = "Stable\\" ascii
    condition: 
        uint16(0) == 0x5a4d and 5 of them
}