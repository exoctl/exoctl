#pragma once

#include <toml++/toml.hpp>

/* if tbl is empty get value directly */
#define GET_TOML_TBL_VALUE(obj, type, tbl, key) obj.toml_get_tbl_##type(tbl, key)

namespace Parser
{
    class Toml
    {
    public:
        Toml();
        ~Toml();

        void toml_parser_file(const std::string &);
        const std::string toml_get_tbl_string(const std::string &, const std::string &);
        const std::uint16_t toml_get_tbl_uint16_t(const std::string &, const std::string &);

    private:
        toml::table m_tbl;
    };
}