rule EXE_SharpilRAT_April_2024 {
    meta:
        author = "NDA0N"
        date = "2024-04-17"
        description = "Detects SharpilRAT executable"
        yarahub_uuid = "3d6d8787-0752-42ab-b22f-d44886e920ac"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "177a73014d3c3455d71d645c1bf32a9f"
    strings:
	$SHARPILRAT = "SHARPIL RAT"  nocase ascii
	$ShowBrwsList = "ShowBrwsList" ascii
	$NordVPN = "NordVPN" ascii
	$OpenVPN = "OpenVPN" ascii
	$ProtonVPN = "ProtonVPN" ascii	
	$FileZilla = "FileZilla" ascii
	$GetClipboardData = "GetClipboardData" ascii
	$CloseClipboard = "CloseClipboard" ascii
	$OpenClipboard = "OpenClipboard" ascii
	$Discord = "Discord" ascii
	$SteamCookie = "SteamCookie" ascii
	$RobloxCookie = "RobloxCookie" ascii
	$Wallets = "Wallets" ascii
    condition:
        ($SHARPILRAT and any of them) or ($ShowBrwsList and 4 of them)
}