@include("elf") 

@sig : "upx" {
    elf.section.text.str_find("Upx 2023")
}