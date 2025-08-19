#pragma once

#include <engine/focades/analysis/binary/lief/pe/entitys.hxx>
#include <engine/parser/binary/lief/lief.hxx>
#include <engine/parser/json/json.hxx>

namespace engine::focades::analysis::binary::pe
{
    class PE
    {
      public:
        PE() = default;
        ~PE() = default;

        void parse_bytes(
            const std::string &,
            const std::function<void(binary::pe::record::DTO *)> &);
        const ::engine::parser::json::Json dto_json(binary::pe::record::DTO *);

      private:
        ::engine::parser::binary::LIEF<const LIEF::PE::Binary,
                                       const LIEF::PE::Parser>
            m_pe;
    };
} // namespace engine::focades::analysis::binary::pe
