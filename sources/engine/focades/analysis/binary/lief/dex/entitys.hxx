#pragma once

#include <engine/parser/binary/lief/lief.hxx>

namespace engine::focades::analysis::binary::dex
{
    namespace record
    {
        typedef struct DTO {
            std::unique_ptr<const LIEF::DEX::File> *dex;
        } DTO;
    } // namespace record
} // namespace engine::focades::analysis::binary::dex