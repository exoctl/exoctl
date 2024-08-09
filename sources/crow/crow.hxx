#pragma once

#define CROW_ENFORCE_WS_SPEC

#include <crow.h>

#include "toml.hxx"

namespace Crow
{
    class Crow
    {
    private:
        const std::uint16_t m_port;
        const std::string m_bindaddr;
        crow::SimpleApp m_app;
        Parser::Toml &m_config;

    public:
        Crow(Parser::Toml &);
        ~Crow();

        crow::SimpleApp &crow_get_app();
        Parser::Toml &crow_get_config();
        void crow_run();
    };
};