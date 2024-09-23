#pragma once

#include <engine/disassembly/capstone/capstone.hxx>
#include <engine/parser/elf.hxx>

namespace Decompiler
{
    class CElf
    {
      public:
        ~CElf();
        CElf();

        const bool celf_parser_file();
        const bool celf_parser_bytes();

      private:
        Disassembly::Capstone *m_capstone;
        Parser::Elf *m_elf;
    };
} // namespace Decompiler