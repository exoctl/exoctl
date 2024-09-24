#pragma once

#include <engine/disassembly/capstone/capstone.hxx>
#include <engine/parser/elf.hxx>

namespace Decompiler
{
    namespace C
    {
        class CElf
        {
          public:
            ~CElf();
            CElf();

            const bool celf_parser_file(const std::string &);
            const bool celf_parser_bytes(const std::string &);

          private:
            Disassembly::Capstone *m_capstone;
            Parser::Elf m_elf;
        };
    } // namespace C
} // namespace Decompiler