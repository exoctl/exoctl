#pragma once

#include <toml++/toml.hpp>

namespace Parser
{
    class Toml
    {
    public:
        Toml();
        ~Toml();

        void toml_parser_file(const std::string&);
        

    private:
        toml::table m_tbl;

    };
}