#pragma once

#include <engine/disassembly/capstone/capstone.hxx>
#include <engine/parser/elf.hxx>

namespace Decompiler
{
    class PseudoCElf
    {
      public:
        ~PseudoCElf();
        PseudoCElf();

      private:
        Disassembly::Capstone *m_capstone;
        Parser::Elf *m_elf;
    };
} // namespace Decompiler