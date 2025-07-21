#pragma once

#include <engine/parser/binary/lief/lief.hxx>

namespace engine::bridge::focades::analysis::binary::elf
{
    namespace record
    {
        typedef struct DTO {
            std::unique_ptr<const LIEF::ELF::Binary> *elf;
        } DTO;
    } // namespace record
} // namespace engine::bridge::focades::analysis::binary::elf