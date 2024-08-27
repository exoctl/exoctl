#include <engine/crow/crow.hxx>
#include <engine/crow/crow_exception.hxx>

namespace Crow
{
Crow::Crow(Parser::Toml &p_config, Logging::Log &p_log)
    : m_config(p_config), m_log(p_log),
      m_port(GET_TOML_TBL_VALUE(p_config, uint16_t, "crow", "port")),
      m_bindaddr(GET_TOML_TBL_VALUE(p_config, string, "crow", "bindaddr"))
{
}

Crow::~Crow() {}

void Crow::crow_run()
{
    m_app.bindaddr(m_bindaddr).port(m_port).multithreaded().run();
}

void Crow::crow_stop() { m_app.multithreaded().stop(); }

void Crow::crow_abort(const std::string &p_reason)
{
    LOG(m_log, error, "Crow aborted due to: {}", p_reason);
    throw CrowException::Abort(p_reason);
}

Parser::Toml &Crow::crow_get_config() { return m_config; }

crow::SimpleApp &Crow::crow_get_app() { return m_app; }

Logging::Log &Crow::crow_get_log() { return m_log; }
}; // namespace Crow