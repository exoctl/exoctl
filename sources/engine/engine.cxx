#include <engine/engine.hxx>
#include <engine/exception.hxx>
#include <engine/memory/memory.hxx>
#include <engine/server/exception.hxx>

namespace engine
{
    Engine::Engine(configuration::Configuration &p_configuration,
                   logging::Logging &p_log)
        : m_configuration(p_configuration), m_log(p_log),
          m_server(p_configuration, p_log), m_server_bridge(m_server),
          m_server_log(p_configuration, p_log),
          m_llama_log(p_configuration, p_log),
          m_lief_log(p_configuration, p_log),
#ifdef ENGINE_PRO
          m_plugins(p_configuration, p_log),
#endif
          is_running(false)
    {
    }

#ifdef ENGINE_PRO
    void Engine::register_plugins()
    {
        plugins::Plugins::lua.lua["engine"] = this;

        plugins::Plugins::lua.lua.new_usertype<Engine>(
            "Engine",
            "is_running",
            sol::readonly(&Engine::is_running),
            "stop",
            &Engine::stop,
            "start",
            &Engine::run);

        //  register plugin server
        m_server.register_plugins();
        //
        //// register plugin log
        m_log.register_plugins();
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

        m_server_bridge.load();
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
