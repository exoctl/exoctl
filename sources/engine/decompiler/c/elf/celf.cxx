#include <engine/decompiler/c/elf/celf.hxx>

namespace Decompiler
{
    namespace C
    {
        CElf::~CElf()
        {
        }

        CElf::CElf()
        {
        }

        const bool CElf::celf_parser_file(const std::string &p_file_path)
        {
            bool err = false;

            if (m_elf.elf_parser_file(p_file_path))
                err = true;

            return err;
        }

        const bool CElf::celf_parser_bytes(const std::string &p_buffer)
        {
            return true;
        }
    } // namespace C
} // namespace Decompiler