rule IceFire 
{
	meta:
		author = "vitor mob"
        date = "2023-03-09"
        version = "1"
        description = "Detects IceFire"
		hash_sha256 = "e9cc7fdfa3cf40ff9c3db0248a79f4817b170f2660aa2b2ed6c551eae1c38e0b"
		malware_bazaar = "https://bazaar.abuse.ch/sample/e9cc7fdfa3cf40ff9c3db0248a79f4817b170f2660aa2b2ed6c551eae1c38e0b"

	strings:
		$path = "/home/Jhone/Desktop/result/mopenssldir" wide ascii
		$file_pid = "iFire.pid" wide ascii
		$readme =  "iFire-readme.txt" wide ascii
		$onion = "7kstc545azxeahkduxmefgwqkrrhq3mzohkzqvrv7aekob7z3iwkqvyd.onion" wide ascii
		$buildIDsha1 = { 8bb905571f61b16588ff1630a951a05d02a286d3 }

		$sequence1 = { 48 C7 45 E0 28 8F 58 00 } // mov     [rbp+string_rsa_public_key], offset aBeginRsaPublic
		$sequence2 = { 48 C7 45 E8 F3 90 58 00 } // mov     [rbp+file_name], offset aIfirePid ; "iFire.pid"


	condition:
		any of them

}