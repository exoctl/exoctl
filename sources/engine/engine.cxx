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
          m_lief_log(p_configuration, p_log), m_plugins(p_configuration, p_log),
          is_running(false)
    {
    }

    void Engine::register_plugins()
    {
        int version = ENGINE_VERSION_CODE;
        std::function<std::any()> stop = [&]() -> std::any {
            this->stop();
            return {}; // return nil
        };

        // register plugin engine
        engine::plugins::Plugins::register_class("engine", this);
        engine::plugins::Plugins::register_class_member(
            "engine", "version_code", version);
        engine::plugins::Plugins::register_class_member(
            "engine", "is_running", is_running);
        engine::plugins::Plugins::register_class_method("engine", "stop", stop);

        // register plugin server
        m_server.register_plugins();

        // register plugin log
        m_log.register_plugins();
    }

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

        m_server_bridge.load();
        m_plugins.load();

        if (p_callback) {
            p_callback();
        }

        m_plugins.run();
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
