#pragma once

#include <engine/bridge/focades/parser/binary/lief/pe/entitys.hxx>
#include <engine/parser/binary/lief/lief.hxx>
#include <engine/parser/json/json.hxx>

namespace engine::bridge::focades::parser::binary::pe
{
    class PE
    {
      public:
        PE() = default;
        ~PE() = default;

        void parse_bytes(
            const std::string &,
            const std::function<void(binary::pe::record::DTO *)> &);
        const ::engine::parser::Json dto_json(binary::pe::record::DTO *);

      private:
        ::engine::parser::binary::LIEF<const LIEF::PE::Binary,
                                       const LIEF::PE::Parser>
            m_pe;
    };
} // namespace engine::bridge::focades::parser::binary::pe
