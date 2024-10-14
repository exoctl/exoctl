#pragma once

#include <engine/parser/binary/macho.hxx>

namespace engine
{
    namespace focades
    {
        namespace parser
        {
            namespace binary
            {
                namespace macho
                {
                    namespace record
                    {
                        typedef struct DTO {
                            std::unique_ptr<const LIEF::MachO::FatBinary> *macho;
                        } DTO;
                    } // namespace record
                } // namespace elf
            } // namespace binary
        } // namespace parser
    } // namespace focades
} // namespace engine