#include <atomic>
#include <chrono>
#include <engine/bridge/bridge.hxx>
#include <engine/bridge/exception.hxx>
#include <engine/crypto/sha.hxx>
#include <engine/database/database.hxx>
#include <engine/engine.hxx>
#include <engine/exception.hxx>
#include <engine/llama/llama.hxx>
#include <engine/magic/magic.hxx>
#include <engine/parser/json/json.hxx>
#include <engine/security/yara/extend/yara.hxx>
#include <engine/security/yara/yara.hxx>
#include <thread>

namespace engine
{
    Engine::Engine() : is_running(false)
    {
    }

    Engine::~Engine()
    {
        is_running = false;
    }

    void Engine::setup(configuration::Configuration &p_config,
                       logging::Logging &p_log)
    {
        m_logging = p_log;
        m_configuration = p_config;

        m_database.setup(m_configuration, m_logging);
        m_server.setup(m_configuration, m_logging);
        m_plugins.setup(m_configuration, m_logging);
        m_clamav_log.setup(m_configuration, m_logging);
        m_llama_log.setup(m_configuration, m_logging);
        m_lief_log.setup(m_configuration, m_logging);
        m_server_log.setup(m_configuration, m_logging);
        m_bridge.setup(m_server);

        _plugins();
    }

    void Engine::_plugins()
    {
        m_logging.info("Engine registering plugins...");

        plugins::Plugins::lua.state["_engine"] = this;

        server::extend::Server::plugins();
        logging::extend::Logging::plugins();
        configuration::extend::Configuration::plugins();
        llama::extend::Llama::plugins();
        crypto::extend::Sha::plugins();
        security::yara::extend::Yara::plugins();
        magic::extend::Magic::plugins();
        parser::extend::Json::plugins();
        bridge::extend::Bridge::plugins();
        version::extend::Version::plugins();
        database::extend::Database::plugins();
    }

    void Engine::load()
    {
        m_database.load();
        m_server.load();
        m_bridge.load();
        m_plugins.load();
    }

    void Engine::stop()
    {
        is_running = false;
        m_server.stop();
    }

    void Engine::run()
    {
        is_running = true;
        m_plugins.run_async();
        m_server.run_async();
    }
} // namespace engine
