#pragma once

#include <toml++/toml.hpp>

#define GET_TOML_TBL_VALUE(obj, type, tbl, key)                                \
    obj.toml_get_tbl_##type(tbl, key)

#define GET_TOML_VALUE(obj, type, key) obj.toml_get_tbl_##type(key)

namespace Parser
{
    class Toml
    {
      public:
        Toml();
        ~Toml();

        void toml_parser_file(const std::string &);

        // TODO: implement type return for demand
        [[nodiscard]] const std::string toml_get_tbl_string(
            const std::string &, const std::string &);
        [[nodiscard]] const std::uint16_t toml_get_tbl_uint16_t(
            const std::string &, const std::string &);

        [[nodiscard]] const toml::array toml_get_tbl_array(const std::string &,
                                                           const std::string &);

        [[nodiscard]] const std::string toml_get_tbl_string(
            const std::string &);
        [[nodiscard]] const std::uint16_t toml_get_tbl_uint16_t(
            const std::string &);

        [[nodiscard]] const toml::array toml_get_tbl_array(const std::string &);

      private:
        toml::table m_tbl;
    };
} // namespace Parser