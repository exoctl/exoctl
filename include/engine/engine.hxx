#pragma once

#include <engine/crowapp/crowapp.hxx>
#include <engine/crowapp/log/log.hxx>
#include <engine/crowapp/bridge/bridge.hxx>
#include <engine/logging.hxx>
#include <engine/parser/toml.hxx>
#include <functional>

namespace engine
{
    class Engine
    {
      private:
        parser::Toml &m_configuration;
        logging::Logging m_log;
        crowapp::CrowApp m_crow;
        crowapp::Bridge m_crow_bridge;
        crowapp::Log m_crow_log;

      public:
        Engine(parser::Toml &);
        ~Engine();

        [[nodiscard]] const std::string &engine_bindaddr();
        [[nodiscard]] const uint16_t &engine_port();
        [[nodiscard]] const uint16_t engine_concurrency();

        [[nodiscard]] const std::vector<crowapp::bridge::record::Bridge> &
        engine_routes();
        void engine_stop();
        void engine_run(const std::function<void()> & = nullptr);
    };
} // namespace Engine
