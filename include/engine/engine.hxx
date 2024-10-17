#pragma once

#include <engine/parser/binary/lief/_/log.hxx>
#include <engine/configuration/configuration.hxx>
#include <engine/crowapp/_/log/log.hxx>
#include <engine/crowapp/bridge/bridge.hxx>
#include <engine/crowapp/crowapp.hxx>
#include <engine/logging.hxx>
#include <engine/parser/toml.hxx>
#include <functional>

namespace engine
{
    class Engine
    {
      private:
        configuration::Configuration &m_configuration;
        logging::Logging &m_log;

        crowapp::CrowApp m_crowapp;
        crowapp::Bridge m_crowapp_bridge;
        crowapp::_::Log m_crowapp_log;
        parser::binary::lief::_::Log m_lief_log;

      public:
        Engine(configuration::Configuration &, logging::Logging &);
        ~Engine();

        [[nodiscard]] const std::string &get_bindaddr();
        [[nodiscard]] const uint16_t &get_port();
        [[nodiscard]] const uint16_t get_concurrency();

        void stop();
        void run(const std::function<void()> & = nullptr);
    };
} // namespace engine
