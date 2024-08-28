#include <engine/crow/crow.hxx>
#include <engine/crow/crow_exception.hxx>

namespace Crow
{
Crow::Crow(Parser::Toml &p_config, Logging::Log &p_log)
    : m_config(p_config), m_log(p_log),
      m_port(GET_TOML_TBL_VALUE(p_config, uint16_t, "crow", "port")),
      m_bindaddr(GET_TOML_TBL_VALUE(p_config, string, "crow", "bindaddr")),
      m_logger(p_log)
{
    crow::logger::setHandler(&m_logger);
}

Crow::~Crow() {}

void Crow::crow_run()
{
    m_app.bindaddr(m_bindaddr).port(m_port).multithreaded().run();
}

void Crow::crow_stop() { m_app.multithreaded().stop(); }

Parser::Toml &Crow::crow_get_config() { return m_config; }

crow::SimpleApp &Crow::crow_get_app() { return m_app; }

Logging::Log &Crow::crow_get_log() { return m_log; }
}; // namespace Crow