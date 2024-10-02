#include <engine/crow/crow_exception.hxx>
#include <engine/engine.hxx>
#include <engine/engine_exception.hxx>
#include <engine/memory.hxx>

namespace Engine
{

    Engine::Engine(Parser::Toml &p_configuration)
        : m_configuration(p_configuration), m_log(p_configuration),
          m_crow(p_configuration, m_log), m_crow_routes(m_crow),
          m_crow_log(m_crow)
    {
    }

    Engine::~Engine()
    {
    }

    void Engine::engine_stop()
    {
        m_crow.crow_stop();
    }

    const std::string &Engine::engine_bindaddr()
    {
        return m_crow.crow_bindaddr();
    }

    const uint16_t &Engine::engine_port()
    {
        return m_crow.crow_port();
    }

    const uint16_t Engine::engine_concurrency()
    {
        return m_crow.crow_get_concurrency();
    }

    void Engine::engine_run(const std::function<void()> &p_callback)
    {
        TRY_BEGIN()
        m_crow_routes.routes_init();
        (!IS_NULL(p_callback)) ? p_callback() : (void) 0;
        m_crow.crow_run();
        TRY_END()
        CATCH(Crow::CrowException::Abort, {
            LOG(m_log,
                error,
                "Critical Crow aborted. Engine stopping. Reason: {}",
                e.what());
            engine_stop();
            throw EngineException::Run("Operation failed, Crow was aborted: " +
                                       std::string(e.what()));
        })
        CATCH(Crow::CrowException::ParcialAbort,
              { LOG(m_log, error, "Non-critical occurred: {}", e.what()); })
    }

    const std::vector<Crow::Structs::Endpoints> &Engine::engine_routes()
    {
        return m_crow_routes.routes_get_endpoints();
    }
} // namespace Engine
