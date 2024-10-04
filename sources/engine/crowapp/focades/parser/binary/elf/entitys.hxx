#pragma once

#include <engine/parser/binary/elf.hxx>
#include <string>

namespace focades
{
    namespace parser
    {
        namespace binary
        {
            namespace elf
            {
                namespace record
                {
                    typedef struct DTO {
                        LIEF::ELF::Header elf_header;
                    } DTO;
                } // namespace record
            } // namespace elf
        } // namespace binary
    } // namespace parser
} // namespace focades