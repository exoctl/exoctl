#pragma once

#include <LIEF/ELF.hpp>

namespace Parser
{
    namespace Binary
    {
        class ELF : public LIEF::ELF::Parser
        {
          public:
            ELF();
            ~ELF();

            void elf_parser_bytes(
                const std::string &,
                const std::function<void(std::unique_ptr<const LIEF::ELF::Binary>)>
                    &);

            void elf_parser_file(
                const std::string &,
                const std::function<void(std::unique_ptr<const LIEF::ELF::Binary>)>
                    &);
        };
    } // namespace Binary
} // namespace Parser