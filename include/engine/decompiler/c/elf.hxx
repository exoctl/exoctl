#pragma once

#include <engine/decompiler/entitys.hxx>
#include <engine/disassembly/capstone/capstone.hxx>
#include <engine/parser/binary/elf.hxx>

namespace decompiler
{
    namespace C
    {
        class ELF
        {
          public:
            ~ELF();
            ELF();

            const bool parser_file(const std::string &);
            const bool parser_bytes(const std::string &);

            void init_function(record::Function *, uint64_t, uint64_t);

          private:
            disassembly::Capstone *m_capstone;
            parser::binary::ELF m_elf;
        };
    } // namespace C
} // namespace Decompiler