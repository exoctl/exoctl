#include <engine/engine.hxx>

namespace Engine
{

Engine::Engine(Parser::Toml &p_configuration)
    : m_configuration(p_configuration), m_log(p_configuration),
      m_crow(p_configuration, m_log), // m_database(p_configuration, m_log),
      m_routes(m_crow)
{
}

Engine::~Engine() {}

void Engine::engine_stop() {}
void Engine::engine_run()
{
    m_routes.routes_create();
    m_crow.crow_run();
}

} // namespace Engine