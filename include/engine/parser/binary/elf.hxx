#pragma once

#include <LIEF/ELF.hpp>

namespace Parser
{
    namespace Binary
    {
        class ELF : public LIEF::ELF::Binary
        {
          private:
            std::unique_ptr<const LIEF::ELF::Binary> m_elf;

          public:
            ELF();
            ~ELF();

            std::unique_ptr<const LIEF::ELF::Binary> &elf_parser_buffer(
                const std::string &);

            std::unique_ptr<const LIEF::ELF::Binary> &elf_parser_file(
                const std::string &);
        };
    } // namespace Binary
} // namespace Parser