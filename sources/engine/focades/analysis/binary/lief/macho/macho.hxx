#pragma once

#include <engine/focades/analysis/binary/lief/macho/entitys.hxx>
#include <engine/parser/binary/lief/lief.hxx>
#include <engine/parser/json/json.hxx>

namespace engine::focades::analysis::binary::macho
{
    class MACHO
    {
      public:
        MACHO() = default;
        ~MACHO() = default;

        void parse_bytes(
            const std::string &,
            const std::function<void(binary::macho::record::DTO *)> &);
        const ::engine::parser::json::Json dto_json(binary::macho::record::DTO *);

      private:
        ::engine::parser::binary::LIEF<const LIEF::MachO::FatBinary,
                                       const LIEF::MachO::Parser>
            macho_;
    };
} // namespace engine::focades::analysis::binary::macho