#include "toml.hxx"

namespace Parser
{
    void Toml::toml_parser_file(const std::string &p_filepath)
    {
        m_tbl = toml::parse_file(p_filepath);
    }

    Toml::Toml()
    {
    }

    Toml::~Toml()
    {
    }
}