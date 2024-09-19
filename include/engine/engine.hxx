#pragma once

#include <engine/crow/crow.hxx>
#include <engine/crow/log/log.hxx>
#include <engine/crow/routes/routes.hxx>
#include <engine/database/postgresql.hxx>
#include <engine/log.hxx>
#include <engine/parser/toml.hxx>
#include <functional>

namespace Engine
{

    class Engine
    {
      private:
        Parser::Toml &m_configuration;
        Logging::Log m_log;
        // Database::Postgresql m_database;
        Crow::CrowApp m_crow;
        Crow::Routes m_crow_routes;
        Crow::Log m_crow_log;

      public:
        Engine(Parser::Toml &);
        ~Engine();

        const std::string &engine_bindaddr();
        const uint16_t &engine_port();

        const std::vector<Crow::Structs::Endpoints> &engine_routes();
        void engine_stop();
        void engine_run(const std::function<void()> & = nullptr);
    };

} // namespace Engine