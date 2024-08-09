#include "crow.hxx"

namespace Crow
{
    Crow::Crow(Parser::Toml &p_config) : m_config(p_config),
                                               m_port(GET_TOML_TBL_VALUE(p_config, uint16_t, "crow", "port")),
                                               m_bindaddr(GET_TOML_TBL_VALUE(p_config, string, "crow", "bindaddr"))
    {
        m_app.loglevel(crow::LogLevel::Info);
    }

    Crow::~Crow()
    {
    }

    void Crow::crow_run()
    {
        m_app.bindaddr(m_bindaddr).port(m_port).multithreaded().run();
    }

    Parser::Toml &Crow::crow_get_config()
    {
        return m_config;
    }

    crow::SimpleApp &Crow::crow_get_app()
    {
        return m_app;
    }
};