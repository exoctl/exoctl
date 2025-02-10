#include <atomic>
#include <chrono>
#include <engine/engine.hxx>
#include <engine/exception.hxx>
#include <engine/memory/memory.hxx>
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
        m_log = p_log;
        m_configuration = p_config;

#ifdef ENGINE_PRO
        m_plugins.setup(m_configuration, m_log);
#endif
        m_clamav_log.setup(m_configuration, m_log);
        m_llama_log.setup(m_configuration, m_log);
        m_lief_log.setup(m_configuration, m_log);
        m_server_log.setup(m_configuration, m_log);

        m_server.setup(m_configuration, m_log);
        m_server_bridge.setup(m_server);
    }

    void Engine::bind_to_lua(sol::state_view &p_lua)
    {
        memory.bind_to_lua(p_lua);
        
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
            "run",
            &Engine::run,
            "load",
            &Engine::load,
            "memory",
            &Engine::memory);
    }

#ifdef ENGINE_PRO
    void Engine::register_plugins()
    {
        plugins::Plugins::lua.state["_engine"] = this;

        plugins::Plugins::lua.state.new_usertype<engine::Engine>(
            "Engine",
            sol::constructors<engine::Engine()>(),
            "is_running",
            sol::readonly(&Engine::is_running),
            "stop",
            &Engine::stop,
            "setup",
            &Engine::setup,
            "run",
            &Engine::run,
            "load",
            &Engine::load);

        //  register plugin server
        m_server.register_plugins();

        // register plugin bridge
        m_server_bridge.register_plugins();
    }
#endif

    void Engine::load()
    {
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

    void Engine::run(const std::function<void()> &p_callback)
    {
        is_running = true;

        TRY_BEGIN()

        if (p_callback) {
            std::jthread([this, p_callback]() {
                while (is_running) {
                    p_callback();
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }
            }).detach();
        }

#ifdef ENGINE_PRO
        m_plugins.run();
#endif
        m_server.run();

        TRY_END()
        CATCH(server::exception::Abort, {
            LOG(m_log,
                error,
                "Critical Crow aborted. Engine stopping. Reason: {}",
                e.what());
            Engine::stop();
            throw exception::Run("Operation failed, Crow was aborted: " +
                                 std::string(e.what()));
        })
        CATCH(server::exception::ParcialAbort,
              { LOG(m_log, error, "Non-critical occurred: {}", e.what()); })

        is_running = false;
    }
} // namespace engine
