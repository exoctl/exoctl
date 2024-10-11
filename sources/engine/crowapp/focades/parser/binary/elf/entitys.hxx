#pragma once

#include <engine/parser/binary/elf.hxx>
#include <vector>

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
                        LIEF::ELF::Header header;
                        std::vector<LIEF::ELF::Section> sections;
                    } DTO;
                } // namespace record
            } // namespace elf
        } // namespace binary
    } // namespace parser
} // namespace focades