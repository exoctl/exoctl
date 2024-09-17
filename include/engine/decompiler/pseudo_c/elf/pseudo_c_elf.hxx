#pragma once

#include <engine/disassembly/capstone/capstone.hxx>

namespace Decompiler
{
    class PseudoCElf
    {
      public:
        ~PseudoCElf();
        PseudoCElf();

      private:
        Disassembly::Capstone *m_capstone;
    };
} // namespace Decompiler