#pragma once

#include <engine/bridge/bridge.hxx>
#include <engine/configuration/configuration.hxx>
#include <engine/database/database.hxx>
#include <engine/llama/_/log.hxx>
#include <engine/logging/logging.hxx>
#include <engine/lua/lua.hxx>
#include <engine/memory/memory.hxx>
#include <engine/parser/binary/lief/_/log.hxx>
#include <engine/plugins/plugins.hxx>
#include <engine/security/av/clamav/_/log.hxx>
#include <engine/server/_/log/log.hxx>
#include <engine/server/server.hxx>
#include <engine/signals/signals.hxx>
#include <engine/version/version.hxx>
#include <engine/filesystem/filesystem.hxx>

namespace engine
{
    class Engine : public interface::IPlugins<Engine>
    {
      private:
        // signals::Signals m_signals;
        server::_::Log m_server_log;
        llama::_::Log m_llama_log;
        security::av::clamav::_::Log m_clamav_log;
        parser::binary::lief::_::Log m_lief_log;

      public:
        bool is_running;

        configuration::Configuration configuration;
        logging::Logging logging;
        server::Server server;
        database::Database database;
        plugins::Plugins plugins;
        version::Version version;
        bridge::Bridge bridge;
        filesystem::Filesystem filesystem;

        ~Engine();
        Engine();

        void _plugins() override;

        void setup(configuration::Configuration &, logging::Logging &);

        void load();
        void run();
        void stop();
    };
} // namespace engine