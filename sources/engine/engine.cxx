#include <atomic>
#include <chrono>
#include <engine/bridge/bridge.hxx>
#include <engine/bridge/exception.hxx>
#include <engine/crypto/sha.hxx>
#include <engine/engine.hxx>
#include <engine/exception.hxx>
#include <engine/llama/llama.hxx>
#include <engine/magic/magic.hxx>
#include <engine/parser/json/json.hxx>
#include <engine/security/yara/extend/yara.hxx>
#include <engine/security/yara/yara.hxx>
#include <thread>

namespace engine
{
    Engine::Engine() : is_running(false)
    {
    }

    Engine::~Engine()
    {
        is_running = false;
    }

    void Engine::setup(configuration::Configuration &p_config,
                       logging::Logging &p_log,
                       server::Server &p_server)
    {
        m_logging = p_log;
        m_server = p_server;
        m_configuration = p_config;

        m_plugins.setup(m_configuration, m_logging);
        m_clamav_log.setup(m_configuration, m_logging);
        m_llama_log.setup(m_configuration, m_logging);
        m_lief_log.setup(m_configuration, m_logging);
        m_server_log.setup(m_configuration, m_logging);
        m_server.setup(m_configuration, m_logging);
    }

    void Engine::bind_to_lua(engine::lua::StateView &p_lua)
    {
        p_lua.new_usertype<engine::Engine>(
            "Engine",
            sol::constructors<engine::Engine()>(),
            "is_running",
            sol::readonly(&Engine::is_running),
            "stop",
            &Engine::stop,
            "register_plugins",
            &Engine::register_plugins,
            "setup",
            &Engine::setup,
            "load_emergency",
            &Engine::load_emergency,
            "run",
            &Engine::run,
            "register_emergency",
            &Engine::register_emergency,
            "load",
            &Engine::load,
            "logging",
            &Engine::m_logging,
            "configuration",
            &Engine::m_configuration,
            "server",
            &Engine::m_server,
            "version",
            &Engine::m_version);
    }

    void Engine::register_plugins()
    {
        plugins::Plugins::lua.state["_engine"] = this;

        Engine::bind_to_lua(plugins::Plugins::lua.state);

        server::extend::Server::plugins();
        logging::extend::Logging::plugins();
        configuration::extend::Configuration::plugins();
        llama::extend::Llama::plugins();
        crypto::extend::Sha::plugins();
        security::yara::extend::Yara::plugins();
        magic::extend::Magic::plugins();
        parser::extend::Json::plugins();
        engine::bridge::extend::Bridge::plugins();
        version::extend::Version::plugins();
    }

    void Engine::load()
    {
        Engine::load_emergency();
        m_plugins.load();
    }

    void Engine::stop()
    {
        is_running = false;
        m_server.stop();
    }

    void Engine::register_emergency(
        const int p_sig,
        std::function<void(int, siginfo_t *, void *)> p_handler)
    {
        m_map_emergencys[p_sig] = p_handler;
    }

    void Engine::load_emergency()
    {
        for (const auto &entry : m_map_emergencys) {
            const int sig = entry.first;
            m_emergency.receive_signal(
                sig, [this, sig](int signal, siginfo_t *info, void *context) {
                    if (m_map_emergencys.contains(sig)) {
                        m_map_emergencys[sig](signal, info, context);
                    }
                });
        }
    }

    void Engine::run(const std::function<void()> &p_callback)
    {
        is_running = true;

        if (p_callback) {
            std::jthread([this, p_callback]() {
                while (is_running) {
                    p_callback();
                    std::this_thread::sleep_for(std::chrono::milliseconds(200));
                }
            }).detach();
        }

        m_plugins.run_async();
        m_server.run_async(); /* do not move the output to a variable */

        is_running = false;
    }
} // namespace engine