@include("elf") 

@sig : "upx" {

    meta {
        description="simple sig for detect upx packed in elf"
        author="remob"
    }

    main {
        elf.section.text.str_find("Upx 2023")
    }
}