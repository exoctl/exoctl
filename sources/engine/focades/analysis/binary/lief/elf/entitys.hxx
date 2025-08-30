#pragma once

#include <engine/parser/binary/lief/lief.hxx>

namespace engine::focades::analysis::binary::elf
{
    namespace record
    {
        typedef struct DTO {
            std::unique_ptr<const LIEF::ELF::Binary> *elf;
        } DTO;
    } // namespace record
} // namespace engine::focades::analysis::binary::elf