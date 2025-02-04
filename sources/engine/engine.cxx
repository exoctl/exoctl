#include <engine/engine.hxx>
#include <engine/exception.hxx>
#include <engine/memory/memory.hxx>
#include <engine/server/exception.hxx>

namespace engine
{
    // Engine::Engine(configuration::Configuration &p_configuration,
    //                logging::Logging &p_log)
    //     : m_server(p_configuration, p_log), m_server_bridge(m_server),
    //       m_server_log(p_configuration, p_log),
    //       m_llama_log(p_configuration, p_log),
    //       m_lief_log(p_configuration, p_log),
    // is_running(false)
    //{
    //}

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
        m_server.setup(m_configuration, m_log);
        m_server_log.setup(m_configuration, m_log);
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
            "register_plugins",
            &Engine::register_plugins,
            "setup",
            &Engine::setup,
            "run",
            &Engine::run);
    }

#ifdef ENGINE_PRO
    void Engine::register_plugins()
    {
        plugins::Plugins::lua.state["engine"] = this;

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
            &Engine::run);

        //  register plugin server
        m_server.register_plugins();

        // register plugin bridge
        m_server_bridge.register_plugins();
    }
#endif

    void Engine::stop()
    {
        Engine::finalize();
        m_server.stop();
    }

    void Engine::finalize()
    {
        is_running = false;
    }

    void Engine::run(const std::function<void()> &p_callback)
    {
        is_running = true;

        TRY_BEGIN()
        if (p_callback) {
            p_callback();
        }

        // m_server_bridge.load();
#ifdef ENGINE_PRO
        m_plugins.load();
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

        Engine::finalize();
    }
} // namespace engine
