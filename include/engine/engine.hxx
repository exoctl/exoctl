#pragma once

#include <engine/crow/crow.hxx>
#include <engine/crow/log/log.hxx>
#include <engine/crow/routes/routes.hxx>
#include <engine/database/postgresql.hxx>
#include <engine/log.hxx>
#include <engine/parser/toml.hxx>

namespace Engine
{

class Engine
{
  private:
    Logging::Log m_log;
    // Database::Postgresql m_database;
    Crow::CrowApp m_crow;
    Crow::Routes m_crow_routes;
    Crow::Log m_crow_log;
    Parser::Toml &m_configuration;

  public:
    Engine(Parser::Toml &);
    ~Engine();

    void engine_stop();
    void engine_run();
};

} // namespace Engine