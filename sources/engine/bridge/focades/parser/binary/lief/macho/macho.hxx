#pragma once

#include <engine/parser/binary/lief/lief.hxx>
#include <engine/parser/json/json.hxx>
#include <engine/bridge/focades/parser/binary/lief/macho/entitys.hxx>

namespace engine::bridge::focades::parser::binary::macho
{
    class MACHO
    {
      public:
        MACHO() = default;
        ~MACHO() = default;

        void parse_bytes(
            const std::string &,
            const std::function<void(binary::macho::record::DTO *)> &);
        const ::engine::parser::Json dto_json(binary::macho::record::DTO *);

      private:
        ::engine::parser::binary::LIEF<const LIEF::MachO::FatBinary,
                                       const LIEF::MachO::Parser>
            m_macho;
    };
} // namespace engine::bridge::focades::parser::binary