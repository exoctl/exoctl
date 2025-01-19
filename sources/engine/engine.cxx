#include <engine/engine.hxx>
#include <engine/exception.hxx>
#include <engine/memory/memory.hxx>
#include <engine/server/exception.hxx>

namespace engine
{
    Engine::Engine(configuration::Configuration &p_configuration,
                   logging::Logging &p_log)
        : m_configuration(p_configuration), m_log(p_log),
          SERVER_INSTANCE(p_configuration, p_log),
          m_server_bridge(SERVER_INSTANCE),
          m_server_log(p_configuration, p_log),
          m_llama_log(p_configuration, p_log),
          m_lief_log(p_configuration, p_log), m_plugins(p_configuration, p_log),
          is_running(false)
    {
#include <engine/_plugins.inc>
    }

    Engine::~Engine()
    {
        is_running = false;
        m_plugins.finalize();
    }

    void Engine::stop()
    {
        is_running = false;
        SERVER_INSTANCE.stop();
    }

    void Engine::run(const std::function<void()> &p_callback)
    {
        is_running = true;

        TRY_BEGIN()

        m_server_bridge.load();
        m_plugins.load();

        (!IS_NULL(p_callback)) ? p_callback() : (void) 0;

        m_plugins.run();

        SERVER_INSTANCE.run();

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
    }
} // namespace engine
