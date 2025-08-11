#pragma once

#include <engine/focades/analysis/binary/lief/dex/entitys.hxx>
#include <engine/parser/binary/lief/lief.hxx>
#include <engine/parser/json/json.hxx>

namespace engine::focades::analysis::binary::dex
{
    class DEX
    {
      public:
        DEX() = default;
        ~DEX() = default;

        void parse_bytes(
            const std::string &,
            const std::function<void(binary::dex::record::DTO *)> &);
        const ::engine::parser::Json dto_json(binary::dex::record::DTO *);

      private:
        ::engine::parser::binary::LIEF<const LIEF::DEX::File,
                                       const LIEF::DEX::Parser>
            m_dex;
    };
} // namespace engine::focades::analysis::binary::dex