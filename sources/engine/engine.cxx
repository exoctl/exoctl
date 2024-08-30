#include <engine/crow/crow_exception.hxx>
#include <engine/engine.hxx>
#include <engine/engine_exception.hxx>

namespace Engine
{

Engine::Engine(Parser::Toml &p_configuration)
    : m_configuration(p_configuration), m_log(p_configuration),
      m_crow(p_configuration, m_log), /* m_database(p_configuration, m_log),*/
      m_crow_routes(m_crow), m_crow_log(m_crow)
{
}

Engine::~Engine() {}

void Engine::engine_stop() { m_crow.crow_stop(); }
void Engine::engine_run()
{
    try
    {
        m_crow_routes.routes_init();
        m_crow.crow_run();
    }
    catch (const Crow::CrowException::Abort &e)
    {
        LOG(m_log, error, "Engine not runned {}", e.what());
        throw EngineException::Run(
            "Operation failed, Crow was aborted : " +
            std::string(e.what()));
    }
}

} // namespace Engine