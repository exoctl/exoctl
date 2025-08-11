#pragma once

#include <engine/parser/binary/lief/lief.hxx>

namespace engine::focades::analysis::binary::macho
{
    namespace record
    {
        typedef struct DTO {
            std::unique_ptr<const LIEF::MachO::FatBinary> *macho;
        } DTO;
    } // namespace record
} // namespace engine::focades::analysis::binary::macho