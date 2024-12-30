#pragma once

#include <engine/configuration/configuration.hxx>
#include <engine/server/_/log/log.hxx>
#include <engine/server/bridge/bridge.hxx>
#include <engine/server/server.hxx>
#include <engine/logging.hxx>
#include <engine/parser/binary/lief/_/log.hxx>
#include <engine/llama/_/log.hxx>
#include <engine/parser/toml.hxx>
#include <functional>

namespace engine
{
    class Engine
    {
      private:
        configuration::Configuration &m_configuration;
        logging::Logging &m_log;

        server::Server m_server;
        server::Bridge m_server_bridge;
        server::_::Log m_server_log;
        
        llama::_::Log m_llama_log;
        parser::binary::lief::_::Log m_lief_log;

      public:
        Engine(configuration::Configuration &, logging::Logging &);
        ~Engine() = default;

        [[nodiscard]] const std::string &get_bindaddr();
        [[nodiscard]] const uint16_t &get_port();
        [[nodiscard]] const uint16_t get_concurrency();

        void stop();
        void run(const std::function<void()> & = nullptr);
    };
} // namespace engine
