#pragma once

#include <toml++/toml.hpp>

#define GET_TOML_TBL_VALUE(obj, type, tbl, key)                                \
    obj.get_tbl_##type(tbl, key)

#define GET_TOML_VALUE(obj, type, key) obj.get_tbl_##type(key)

namespace parser
{
    class Toml
    {
      public:
        Toml();
        ~Toml();

        void parser_file(const std::string &);

        // TODO: implement type return for demand
        [[nodiscard]] const std::string get_tbl_string(
            const std::string &, const std::string &);

        [[nodiscard]] const bool get_tbl_bool(const std::string &,
                                                          const std::string &);
        [[nodiscard]] const std::uint16_t get_tbl_uint16(
            const std::string &, const std::string &);

        [[nodiscard]] const toml::array get_tbl_array(const std::string &,
                                                           const std::string &);

        [[nodiscard]] const std::string get_tbl_string(
            const std::string &);
        [[nodiscard]] const std::uint16_t get_tbl_uint16(
            const std::string &);

        [[nodiscard]] const toml::array get_tbl_array(const std::string &);

      private:
        toml::table m_tbl;
    };
} // namespace Parser