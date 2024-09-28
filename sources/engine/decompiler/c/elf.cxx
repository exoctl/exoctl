#include <engine/decompiler/c/elf.hxx>

namespace Decompiler
{
    namespace C
    {
        ELF::~ELF()
        {
            delete m_capstone;
        }

        ELF::ELF()
        {
        }

        const bool ELF::elf_parser_file(const std::string &p_file_path)
        {
            bool err = false;

            if (m_elf.parse(p_file_path)) {
                err = true;

                // if (m_elf.parse(p_file_path).identity_class() ==
                //     LIEF::ELF::Header::CLASS::ELF32) {
                m_capstone = new Disassembly::Capstone(CS_ARCH_X86, CS_MODE_32);
                //}

                m_capstone = new Disassembly::Capstone(CS_ARCH_X86, CS_MODE_64);
            }

            return err;
        }

        const bool ELF::elf_parser_bytes(const std::string &p_buffer)
        {
            return true;
        }

        void ELF::elf_init_function(Structs::Function *p_func,
                                    uint64_t p_start_function,
                                    uint64_t p_end_function)
        {
            p_func->end_function = p_end_function;
            p_func->start_function = p_start_function;
        }
    } // namespace C
} // namespace Decompiler