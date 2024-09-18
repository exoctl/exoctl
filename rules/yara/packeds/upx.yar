import "elf"

rule ELF_Packed_With_UPX {
    meta:
        description = "Detects ELF files packed with UPX using the ELF module"
        author = "remob"
        date = "2024-09-18"
    
    strings:
        $upx_marker_1 = "UPX!"              
        $upx_marker_2 = "UPX0"              
        $upx_marker_3 = "UPX1"              
    
    condition:
        elf.type == elf.ET_EXEC and         
        elf.number_of_segments > 2 and      
        ($upx_marker_1 or $upx_marker_2 or $upx_marker_3) 
}
