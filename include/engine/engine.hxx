#pragma once

#include <engine/configuration/configuration.hxx>
#include <engine/llama/_/log.hxx>
#include <engine/logging.hxx>
#include <engine/parser/binary/lief/_/log.hxx>
#include <engine/parser/toml.hxx>
#include <engine/plugins/plugins.hxx>
#include <engine/server/_/log/log.hxx>
#include <engine/server/bridge/bridge.hxx>
#include <engine/server/server.hxx>
#include <functional>


#define SERVER_INSTANCE m_server

namespace engine
{
    class Engine
    {
      private:
        configuration::Configuration &m_configuration;
        logging::Logging &m_log;

        server::Server SERVER_INSTANCE;
        server::Bridge m_server_bridge;
        server::_::Log m_server_log;

        llama::_::Log m_llama_log;
        parser::binary::lief::_::Log m_lief_log;

        plugins::Plugins m_plugins;

      public:
        bool is_running;

        Engine(configuration::Configuration &, logging::Logging &);
        ~Engine();

        void stop();
        void run(const std::function<void()> & = nullptr);
    };
} // namespace engine
