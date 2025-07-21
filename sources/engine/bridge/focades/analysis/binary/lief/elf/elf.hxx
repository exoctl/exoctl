#pragma once

#include <engine/bridge/focades/analysis/binary/lief/elf/entitys.hxx>
#include <engine/parser/binary/lief/lief.hxx>
#include <engine/parser/json/json.hxx>

namespace engine::bridge::focades::analysis::binary::elf
{
    class ELF
    {
      public:
        ELF() = default;
        ~ELF() = default;

        void parse_bytes(
            const std::string &,
            const std::function<void(binary::elf::record::DTO *)> &);
        const ::engine::parser::Json dto_json(binary::elf::record::DTO *);

      private:
        ::engine::parser::binary::LIEF<const LIEF::ELF::Binary,
                                       const LIEF::ELF::Parser>
            m_elf;
    };
} // namespace engine::bridge::focades::analysis::binary::elf