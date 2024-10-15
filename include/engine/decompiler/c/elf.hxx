#pragma once

#include <engine/decompiler/entitys.hxx>
#include <engine/disassembly/capstone/capstone.hxx>
#include <engine/parser/binary/lief/lief.hxx>

namespace engine
{
    namespace decompiler
    {
        namespace C
        {
            class ELF
            {
              public:
                ~ELF();
                ELF();

                const bool parse_file(const std::string &);
                const bool parse_bytes(const std::string &);

                void init_function(record::Function *, uint64_t, uint64_t);

              private:
                disassembly::Capstone *m_capstone;
                ::engine::parser::binary::LIEF<const LIEF::ELF::Binary,
                                               const LIEF::ELF::Parser>
                    m_elf;
            };
        } // namespace C
    } // namespace decompiler
} // namespace engine