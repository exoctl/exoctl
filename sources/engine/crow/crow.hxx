#pragma once

#define CROW_ENFORCE_WS_SPEC

#include <crow.h>
#include <engine/log.hxx>
#include <engine/parser/toml.hxx>

namespace Crow
{
class Crow
{
  private:
    const std::uint16_t m_port;
    const std::string m_bindaddr;
    crow::SimpleApp m_app;
    Parser::Toml &m_config;
    Logging::Log &m_log;

  public:
    Crow(Parser::Toml &, Logging::Log &);
    ~Crow();

    crow::SimpleApp &crow_get_app();
    Parser::Toml &crow_get_config();
    Logging::Log &crow_get_log();

    void crow_run();
    void crow_stop();
};
}; // namespace Crow