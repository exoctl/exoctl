#pragma once

#include <engine/parser/binary/lief/lief.hxx>

namespace engine::bridge::focades::parser::binary::macho
{
    namespace record
    {
        typedef struct DTO {
            std::unique_ptr<const LIEF::MachO::FatBinary> *macho;
        } DTO;
    } // namespace record
} // namespace engine::bridge::focades::parser::binary::macho