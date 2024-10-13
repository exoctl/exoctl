#pragma once

#include <toml++/toml.hpp>

namespace engine
{
    namespace parser
    {
        class Toml
        {
          public:
            Toml();
            ~Toml();

            void parse_file(const std::string &);
            void parse_buffer(const std::string_view &);
            const toml::table &get_tbl() const;

          private:
            toml::table m_tbl;
        };
    } // namespace parser
} // namespace engine