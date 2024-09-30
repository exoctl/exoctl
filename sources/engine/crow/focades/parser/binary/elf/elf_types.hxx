#pragma once

#include <engine/parser/binary/elf.hxx>
#include <string>

namespace Focades
{
    namespace Parser
    {
        namespace Binary
        {
            namespace Structs
            {
                typedef struct DTO {
                   LIEF::ELF::Header header;
                } DTO;
            } // namespace Structs
        } // namespace Binary
    } // namespace Parser
} // namespace Focades