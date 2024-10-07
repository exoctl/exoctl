#include <engine/crowapp/exception.hxx>
#include <engine/engine.hxx>
#include <engine/exception.hxx>
#include <engine/memory.hxx>

namespace engine
{
    Engine::Engine(configuration::Configuration &p_configuration,
                   logging::Logging &p_log)
        : m_configuration(p_configuration), m_log(p_log),
          m_crowapp(p_configuration, p_log), m_crowapp_bridge(m_crowapp),
          m_crowapp_log(m_crowapp)
    {
    }

    Engine::~Engine()
    {
    }

    void Engine::stop()
    {
        m_crowapp.stop();
    }

    const std::string &Engine::get_bindaddr()
    {
        return m_crowapp.get_bindaddr();
    }

    const uint16_t &Engine::get_port()
    {
        return m_crowapp.get_port();
    }

    const uint16_t Engine::get_concurrency()
    {
        return m_crowapp.get_concurrency();
    }

    void Engine::run(const std::function<void()> &p_callback)
    {
        TRY_BEGIN()
        m_crowapp_bridge.load();
        (!IS_NULL(p_callback)) ? p_callback() : (void) 0;
        m_crowapp.run();
        TRY_END()
        CATCH(crowapp::exception::Abort, {
            LOG(m_log,
                error,
                "Critical Crow aborted. Engine stopping. Reason: {}",
                e.what());
            Engine::stop();
            throw exception::Run("Operation failed, Crow was aborted: " +
                                 std::string(e.what()));
        })
        CATCH(crowapp::exception::ParcialAbort,
              { LOG(m_log, error, "Non-critical occurred: {}", e.what()); })
    }

    const std::vector<crowapp::bridge::record::Bridge> &Engine::get_routes()
    {
        return m_crowapp_bridge.get_endpoints();
    }
} // namespace engine
