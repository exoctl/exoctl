rule obfs_foreach_object
{
	meta:
		description = "Detects obfuscated ForEach-Object calls from PowerShell beacond deployed by socgholish."
		reference = "https://rerednawyerg.github.io/posts/malwareanalysis/socgholish_part3/#nested-powershell-powershell-beacon"
		date = "2024-05-21"
		yarahub_uuid = "3da5d547-62f6-4842-bc4a-cd8937201581"
		yarahub_license = "CC0 1.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_reference_md5 = "a50c02a51979a49902606f3c1ee9d698" 
	strings:
		$match = /\)\)\| [a-z]{5,15} \{ \[char\]\$_ \}\)\)/
	condition:
		$match
}