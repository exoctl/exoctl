#pragma once

#include <engine/configuration/configuration.hxx>
#include <engine/interfaces/iplugins.hxx>
#include <engine/llama/_/log.hxx>
#include <engine/logging/logging.hxx>
#include <engine/lua/lua.hxx>
#include <engine/parser/binary/lief/_/log.hxx>
#include <engine/parser/toml.hxx>
#include <engine/plugins/plugins.hxx>
#include <engine/server/_/log/log.hxx>
#include <engine/server/bridge/bridge.hxx>
#include <engine/server/server.hxx>
#include <functional>

namespace engine
{
    struct Engine {
      private:
        configuration::Configuration m_configuration;
        logging::Logging m_log;
        server::Server m_server;
        // server::Bridge m_server_bridge;
        // server::_::Log m_server_log;

        // llama::_::Log m_llama_log;
        // parser::binary::lief::_::Log m_lief_log;
        void finalize();

      public:
        bool is_running;

        ~Engine() = default;
        Engine();

        void setup(logging::Logging &, configuration::Configuration &);

        void bind_to_lua(sol::state_view &);
        void stop();
        void run(const std::function<void()> & = nullptr);
    };
} // namespace engine
