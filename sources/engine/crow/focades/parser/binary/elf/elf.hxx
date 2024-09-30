#pragma once

#include <engine/crow/focades/parser/binary/elf/elf_types.hxx>
#include <engine/parser/binary/elf.hxx>
#include <engine/parser/json.hxx>

namespace Focades
{
    namespace Parser
    {
        namespace Binary
        {
            class ELF
            {
              public:
                ELF();
                ~ELF();

                void elf_parser_bytes(
                    const std::string &,
                    const std::function<void(Structs::DTO *)> &);
                const ::Parser::Json elf_dto_json(Structs::DTO *);

              private:
                ::Parser::Json elf_header_json(Structs::DTO *p_dto);

                ::Parser::Binary::ELF m_elf;
            };
        } // namespace Binary
    } // namespace Parser
} // namespace Focades