#pragma once

#include <engine/parser/binary/lief/lief.hxx>

namespace engine::focades::parser::binary::art
{
    namespace record
    {
        typedef struct DTO {
            std::unique_ptr<const LIEF::ART::File> *art;
        } DTO;
    } // namespace record
} // namespace engine::focades::parser::binary::elf