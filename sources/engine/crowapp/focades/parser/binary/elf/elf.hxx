#pragma once

#include <engine/crowapp/focades/parser/binary/elf/entitys.hxx>
#include <engine/parser/binary/elf.hxx>
#include <engine/parser/json.hxx>

namespace focades
{
    namespace parser
    {
        namespace binary
        {
            class ELF
            {
              public:
                ELF();
                ~ELF();

                void elf_parser_bytes(
                    const std::string &,
                    const std::function<void(binary::elf::record::DTO *)> &);
                const ::parser::Json elf_dto_json(binary::elf::record::DTO *);

              private:
                ::parser::Json elf_header_json(binary::elf::record::DTO *p_dto);

                ::parser::binary::ELF m_elf;
            };
        } // namespace Binary
    } // namespace Parser
} // namespace focades