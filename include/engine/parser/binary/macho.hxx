#pragma once

#include <LIEF/MachO.hpp>

namespace engine
{
    namespace parser
    {
        namespace binary
        {
            class MACHO
            {
              public:
                MACHO();
                ~MACHO();
                
                void parser_bytes(
                    const std::string &,
                    const std::function<
                        void(std::unique_ptr<const LIEF::MachO::FatBinary>)> &);

                void parser_file(
                    const std::string &,
                    const std::function<
                        void(std::unique_ptr<const LIEF::MachO::FatBinary>)> &);
            };
        } // namespace binary
    } // namespace parser
} // namespace engine