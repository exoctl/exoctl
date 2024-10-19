#include <engine/decompiler/c/elf.hxx>
#include <memory>

namespace engine
{
    namespace decompiler
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

            const bool ELF::parse_file(const std::string &p_file_path)
            {
                m_elf.parse_file(
                    p_file_path, [&](std::unique_ptr<const LIEF::ELF::Binary>) {
                        m_capstone =
                            new disassembly::Capstone(CS_ARCH_X86, CS_MODE_32);

                        m_capstone =
                            new disassembly::Capstone(CS_ARCH_X86, CS_MODE_64);
                    });

                return true;
            }

            const bool ELF::parse_bytes(const std::string &p_buffer)
            {
                return true;
            }

            void ELF::init_function(record::Function *p_func,
                                    uint64_t p_start_function,
                                    uint64_t p_end_function)
            {
                p_func->end_function = p_end_function;
                p_func->start_function = p_start_function;
            }
        } // namespace C
    } // namespace decompiler
} // namespace engine