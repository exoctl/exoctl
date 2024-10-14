#pragma once

#include <engine/parser/binary/elf.hxx>
#include <vector>

namespace engine
{
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
                            std::unique_ptr<const LIEF::ELF::Binary> *elf;
                        } DTO;
                    } // namespace record
                } // namespace elf
            } // namespace binary
        } // namespace parser
    } // namespace focades
} // namespace engine