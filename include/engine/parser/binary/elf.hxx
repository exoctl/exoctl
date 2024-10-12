#pragma once

#include <LIEF/ELF.hpp>

namespace parser
{
    namespace binary
    {
        class ELF : public LIEF::ELF::Parser
        {
          public:
            ELF();
            ~ELF();

            void parser_bytes(const std::string &,
                              const std::function<void(
                                  std::unique_ptr<const LIEF::ELF::Binary>)> &);

            void parser_file(const std::string &,
                             const std::function<void(
                                 std::unique_ptr<const LIEF::ELF::Binary>)> &);
        };
    } // namespace binary
} // namespace parser