#pragma once

#include <engine/parser/binary/lief/lief.hxx>

namespace engine::focades::parser::binary::pe
{
    namespace record
    {
        typedef struct DTO {
            std::unique_ptr<const LIEF::PE::Binary> *pe;
        } DTO;
    } // namespace record
} // namespace engine::focades::parser::binary::elf