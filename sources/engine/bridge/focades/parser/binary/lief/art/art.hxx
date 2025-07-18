#pragma once

#include <engine/bridge/focades/parser/binary/lief/art/entitys.hxx>
#include <engine/parser/binary/lief/lief.hxx>
#include <engine/parser/json/json.hxx>

namespace engine::bridge::focades::parser::binary::art
{
    class ART
    {
      public:
        ART() = default;
        ~ART() = default;

        void parse_bytes(
            const std::string &,
            const std::function<void(binary::art::record::DTO *)> &);
        const ::engine::parser::Json dto_json(binary::art::record::DTO *);

      private:
        ::engine::parser::binary::LIEF<const LIEF::ART::File,
                                       const LIEF::ART::Parser>
            m_art;
    };
} // namespace engine::bridge::focades::parser::binary::art