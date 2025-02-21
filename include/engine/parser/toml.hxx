#pragma once

#include <toml++/toml.hpp>

namespace engine
{
    namespace parser
    {
        class Toml
        {
          public:
            Toml() = default;
            ~Toml() = default;

            void parse_file(const std::string &);
            void parse_buffer(const std::string_view &);
            toml::table tbl;

          private:
        };
    } // namespace parser
} // namespace engine