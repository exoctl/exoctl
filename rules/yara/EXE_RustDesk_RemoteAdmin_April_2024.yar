rule EXE_RustDesk_RemoteAdmin_April_2024 {
    meta:
        author = "NDA0N"
        date = "2024-04-20"
        description = "Detects RustDesk Remote Admin Tool"
        yarahub_uuid = "9f779028-8d7e-4413-82ec-45be4a8d902b"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "f78e62330c6757d845aa9b348f33e784"
    strings:
	$rustdesk = "rustdesk" ascii
	$RustDeskIddDriver = "RustDeskIddDriver.cer" ascii
	$rustdesk_exe = "rustdesk.exe" ascii
	$dll_librustdesk = "librustdesk.dll" ascii
	$RustDeskIddDriverPath = "\\RustDeskIddDriver\\rustdeskidddriver.cat" ascii
	$dll_RustDeskIddDriverPath = "\\RustDeskIddDriver\\RustDeskIddDriver.dll" ascii
	$RustDeskIddDriverPath2  = "\\RustDeskIddDriver\\RustDeskIddDriver.inf" ascii
	$email = "info@rustdesk.com" ascii	
    condition: 
	$rustdesk and $RustDeskIddDriverPath and 2 of them
}