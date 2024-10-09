#pragma once

#include <toml++/toml.hpp>

#define GET_TOML_TBL_VALUE(obj, type, tbl, key) obj.get_tbl_##type(tbl, key)

#define GET_TOML_VALUE(obj, type, key) obj.get_tbl_##type(key)

namespace parser
{
    class Toml
    {
      public:
        Toml();
        ~Toml();

        void parse_file(const std::string &);
        void parse_buffer(const  std::string_view &);
        const toml::table &get_tbl() const;

      private:
        toml::table m_tbl;
    };
} // namespace parser