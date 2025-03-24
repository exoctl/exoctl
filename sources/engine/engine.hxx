#pragma once

#include <engine/configuration/configuration.hxx>
#include <engine/emergency/emergency.hxx>
#include <engine/interfaces/ibind.hxx>
#include <engine/llama/_/log.hxx>
#include <engine/logging/logging.hxx>
#include <engine/lua/lua.hxx>
#include <engine/memory/memory.hxx>
#include <engine/parser/binary/lief/_/log.hxx>
#include <engine/plugins/plugins.hxx>
#include <engine/security/av/clamav/_/log.hxx>
#include <engine/server/_/log/log.hxx>
#include <engine/server/server.hxx>
#include <engine/version/version.hxx>
#include <functional>
#include <unordered_map>

namespace engine
{
    class Engine : public interface::IBind
#ifdef ENGINE_PRO
        ,
                   public interface::IPlugins
#endif
    {
      private:
        configuration::Configuration m_configuration;
        logging::Logging m_logging;
        version::Version m_version;
#ifdef ENGINE_PRO
        plugins::Plugins m_plugins;
#endif

        server::Server m_server;

        emergency::Emergency m_emergency;
        std::unordered_map<int, std::function<void(int, siginfo_t *, void *)>>
            m_map_emergencys;

        server::_::Log m_server_log;
        llama::_::Log m_llama_log;
        security::av::clamav::_::Log m_clamav_log;
        parser::binary::lief::_::Log m_lief_log;

      public:
        bool is_running;

        ~Engine() = default;
        Engine();

#ifdef ENGINE_PRO
        void register_plugins() override;
#endif
        void bind_to_lua(sol::state_view &) override;
        void register_emergency(const int,
                                std::function<void(int, siginfo_t *, void *)>);
        void setup(configuration::Configuration &,
                   logging::Logging &,
                   server::Server &);

        void load();
        void load_emergency();
        void run(const std::function<void()> & = nullptr);
        void stop();
    };
} // namespace engine