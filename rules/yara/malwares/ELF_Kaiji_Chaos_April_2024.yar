rule ELF_Kaiji_Chaos_April_2024 {
    meta:
        author = "NDA0N"
        date = "2024-04-17"
        description = "Detects Chaos, variant of Kaiji"
        yarahub_uuid = "1d571d91-bfdd-4685-a5ac-14a2c89720d6"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "97a8f67c2c5ab8bed5fd869d6c9810fe"
	malpedia_family = "elf.chaos"
    strings:
        $CHAOS = "CHAOS" nocase ascii
        $chaos_ack = "main.chaos_ack" ascii
        $chaos_cve = "main.chaos_cve" ascii
        $chaos_http = "main.chaos_http" ascii
        $chaos_udp = "main.chaos_udp" ascii
        $chaos_ipspoof = "main.chaos_ipspoof" ascii
        $chaos_ssh = "main.chaos_ssh" ascii nocase
	$chaos_sshread = "main.chaos_sshread" ascii
	$chaos_checkip = "main.chaos_checkip" ascii
	$chaos_sshrsa = "main.chaos_sshrsa" ascii
	$chaos_syn = "main.chaos_syn" ascii
	$chaos_tcp = "main.chaos_tcp" ascii
	$chaos_tls = "main.chaos_tls" ascii	
    condition:
        5 of them
}