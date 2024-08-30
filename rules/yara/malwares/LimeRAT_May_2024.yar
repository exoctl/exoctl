rule LimeRAT_May_2024 {
    meta:
        author = "NDA0E"
        date = "2024-05-03"
        description = "Detects LimeRAT"
        yarahub_uuid = "17c401d9-6737-4731-9b2a-413bb45324a5"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "71e04dd1a7ad7068fa236cb7aeb647b3"
	malpedia_family = "win.limerat"
    strings:
	$schtask = "schtasks /create /f /sc ONLOGON /RL HIGHEST /tn LimeRAT-Admin /tr \"" wide ascii
	$virtualbox_dll = "\\vboxhook.dll" wide ascii 
	$PStart = "!PStart" wide ascii 
	$cmd_ping = "Y21kLmV4ZSAvYyBwaW5nIDAgLW4gMiAmIGRlbCA" wide ascii
	$Closure = "_Closure$__R1-0" ascii
	$PIN_Error = "_PIN Error!" wide ascii
	$USB_Error = "_USB Error!" wide ascii
	$Minning = "Minning..." wide ascii
	$PSend = "!PSend" wide ascii
	$Flood = "Flood!" wide ascii
    condition: 
	$schtask and 4 of them
}