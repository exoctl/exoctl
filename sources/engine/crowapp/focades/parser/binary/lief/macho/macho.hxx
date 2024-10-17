#pragma once

#include <engine/crowapp/focades/parser/binary/lief/macho/entitys.hxx>
#include <engine/parser/binary/lief/lief.hxx>
#include <engine/parser/json.hxx>

namespace engine::focades::parser::binary
{
    class MACHO
    {
      public:
        MACHO();
        ~MACHO();

        void parser_bytes(
            const std::string &,
            const std::function<void(binary::macho::record::DTO *)> &);
        const ::engine::parser::Json dto_json(binary::macho::record::DTO *);

      private:
        ::engine::parser::binary::LIEF<const LIEF::MachO::FatBinary,
                                       const LIEF::MachO::Parser>
            m_macho;
    };
} // namespace engine::focades::parser::binary