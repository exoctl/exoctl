#pragma once

#include <engine/decompiler/decompiler_types.hxx>
#include <engine/disassembly/capstone/capstone.hxx>
#include <engine/parser/binary/elf.hxx>

namespace Decompiler
{
    namespace C
    {
        class ELF
        {
          public:
            ~ELF();
            ELF();

            const bool elf_parser_file(const std::string &);
            const bool elf_parser_bytes(const std::string &);
            
            void elf_init_function(Structs::Function *, uint64_t, uint64_t);

          private:
            Disassembly::Capstone *m_capstone;
            Parser::Binary::ELF m_elf;
        };
    } // namespace C
} // namespace Decompiler