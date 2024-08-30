rule AHK_DarkGate_April_2024 {
    meta:
        author = "NDA0N"
        date = "2024-04-16"
        description = "Detects .ahk payload dropped by DarkGate loader"
        yarahub_uuid = "c5011979-9aaa-4429-adf1-752f88be88dd"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "958cd4a849145b96e92e63ef4e152349"
    strings:
        $NoTrayIcon = "#NoTrayIcon" ascii
        $AScript = "A_ScriptDir . \"\\test.txt\"" ascii
        $DllCallFunction = "DllCall(\"VirtualAlloc\", \"Ptr\", 0, \"UInt\", size, \"UInt\"" ascii
        $Loop = "Loop, % size {" ascii
        $NumPut = "NumPut" ascii
        $A_Index = "(A_Index - 1), \"Char\")" ascii
        $DllCall = "DllCall" ascii
    condition:
        4 of them
}