#include <atomic>
#include <chrono>
#include <engine/crypto/sha.hxx>
#include <engine/engine.hxx>
#include <engine/exception.hxx>
#include <engine/llama/llama.hxx>
#include <engine/magic/magic.hxx>
#include <engine/parser/json/json.hxx>
#include <engine/security/yara/yara.hxx>
#include <engine/server/exception.hxx>
#include <thread>

namespace engine
{
    Engine::Engine() : is_running(false)
    {
    }

    void Engine::setup(configuration::Configuration &p_config,
                       logging::Logging &p_log)
    {
        m_logging = p_log;
        m_configuration = p_config;

#ifdef ENGINE_PRO
        m_plugins.setup(m_configuration, m_logging);
#endif
        m_clamav_log.setup(m_configuration, m_logging);
        m_llama_log.setup(m_configuration, m_logging);
        m_lief_log.setup(m_configuration, m_logging);
        m_server_log.setup(m_configuration, m_logging);

        m_server.setup(m_configuration, m_logging);
        m_server_bridge.setup(m_server);
    }

    void Engine::bind_to_lua(sol::state_view &p_lua)
    {
        p_lua.new_usertype<engine::Engine>(
            "Engine",
            sol::constructors<engine::Engine()>(),
            "is_running",
            sol::readonly(&Engine::is_running),
            "stop",
            &Engine::stop,
#ifdef ENGINE_PRO
            "register_plugins",
            &Engine::register_plugins,
#endif
            "setup",
            &Engine::setup,
            "load_emergency",
            &Engine::load_emergency,
            "run",
            &Engine::run,
            "register_emergency",
            &Engine::register_emergency,
            "load",
            &Engine::load);
    }

#ifdef ENGINE_PRO
    void Engine::register_plugins()
    {
        plugins::Plugins::lua.state["_engine"] = this;
        plugins::Plugins::lua.state["_logging"] = &m_logging;
        plugins::Plugins::lua.state["_configuration"] = &m_configuration;
        plugins::Plugins::lua.state["_server"] = &m_server;

        Engine::bind_to_lua(plugins::Plugins::lua.state);

        // subplugins
        llama::Llama::plugins();
        crypto::Sha::plugins();
        security::Yara::plugins();
        magic::Magic::plugins();
        parser::Json::plugins();

        // plugins
        m_server.register_plugins();
        m_server_bridge.register_plugins();
    }
#endif

    void Engine::load()
    {
        Engine::load_emergency();
        m_server_bridge.load();
#ifdef ENGINE_PRO
        m_plugins.load();
#endif
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
            int sig = entry.first;
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

        TRY_BEGIN()

        if (p_callback) {
            std::jthread([this, p_callback]() {
                while (is_running) {
                    p_callback();
                    std::this_thread::sleep_for(std::chrono::milliseconds(200));
                }
            }).detach();
        }

#ifdef ENGINE_PRO
        m_plugins.run_async();
#endif
        m_server.run_async();

        TRY_END()
        CATCH(server::exception::Abort, {
            LOG(m_logging,
                error,
                "Critical Crow aborted. Engine stopping. Reason: {}",
                e.what());
            Engine::stop();
            throw exception::Run("Operation failed, Crow was aborted: " +
                                 std::string(e.what()));
        })
        CATCH(server::exception::ParcialAbort,
              { LOG(m_logging, error, "Non-critical occurred: {}", e.what()); })

        is_running = false;
    }
} // namespace engine