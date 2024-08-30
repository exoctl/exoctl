rule win_colibriloader : packed loader 
{
  meta:
    author =                    "andretavare5"
    org =                       "BitSight"
    date =                      "2022-09-21"
    description =               "Packed ColibriLoader malware"
    yarahub_author_twitter =    "@andretavare5"
    yarahub_reference_link =    "https://fr3d.hk/blog/colibri-loader-back-to-basics"
    yarahub_malpedia_family =   "win.colibri"
    yarahub_uuid =              "287f394b-2160-4f36-8ab7-bfb95fc75355"
    yarahub_license =           "CC BY-NC-SA 4.0"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp =  "TLP:WHITE"
    yarahub_reference_md5 =     "e0a68b98992c1699876f818a22b5b907"
    
  strings:
    $str1 = "NtUnmapViewOfSct"
    $str2 = "RtlAllocateHeap"
    $str3 = "user32.dll"
    $str4 = "kernel32.dll"
                              
  condition:
    uint16(0) == 0x5A4D and // MZ
    all of them
}