#include "toml.hxx"

#include <iostream>

namespace Parser
{

    Toml::Toml() {}
    Toml::~Toml() {}

    void Toml::toml_parser_file(const std::string &p_filepath)
    {
        m_tbl = toml::parse_file(p_filepath);
    }

    const std::string Toml::toml_get_tbl_string(const std::string &p_tbl, const std::string &p_key)
    {
        return (p_tbl.empty()) ? m_tbl[p_key].value<std::string>().value() : m_tbl[p_tbl][p_key].value<std::string>().value();
    }

    const std::uint16_t Toml::toml_get_tbl_uint16_t(const std::string &p_tbl, const std::string &p_key)
    {
        return (p_tbl.empty()) ? m_tbl[p_key].value<std::uint16_t>().value() : m_tbl[p_tbl][p_key].value<std::uint16_t>().value();
    }
}