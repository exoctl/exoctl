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
          m_lief_log(p_configuration, p_log)
    {
    }

    void Engine::stop()
    {
        m_server.stop();
    }

    const std::string &Engine::get_bindaddr()
    {
        return m_server.get_bindaddr();
    }

    const uint16_t &Engine::get_port()
    {
        return m_server.get_port();
    }

    const uint16_t Engine::get_concurrency()
    {
        return m_server.get_concurrency();
    }

    void Engine::run(const std::function<void()> &p_callback)
    {
        TRY_BEGIN()

        m_server_bridge.load();
        (!IS_NULL(p_callback)) ? p_callback() : (void) 0;
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
    }
} // namespace engine
