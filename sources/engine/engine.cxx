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
                       logging::Logging &p_log,
                       server::Server &p_server,
                       database::Database &p_database)
    {
        m_logging = p_log;
        m_configuration = p_config;
        m_server = p_server;
        m_database = &p_database;

        m_plugins.setup(m_configuration, m_logging);
        m_clamav_log.setup(m_configuration, m_logging);
        m_llama_log.setup(m_configuration, m_logging);
        m_lief_log.setup(m_configuration, m_logging);
        m_server_log.setup(m_configuration, m_logging);

        _plugins();
    }

    void Engine::lua_open_library(engine::lua::StateView &p_lua)
    {
        p_lua.new_usertype<engine::Engine>(
            "Engine",
            sol::constructors<engine::Engine()>(),
            "is_running",
            sol::readonly(&Engine::is_running),
            "stop",
            &Engine::stop,
            "setup",
            &Engine::setup,
            "run",
            &Engine::run,
            "load",
            &Engine::load,
            "logging",
            &Engine::m_logging,
            "configuration",
            &Engine::m_configuration,
            "server",
            &Engine::m_server,
            "database",
            &Engine::m_database,
            "version",
            &Engine::m_version);
    }

    void Engine::_plugins()
    {
        m_logging.info("Engine Loading plugins...");

        plugins::Plugins::lua.state["_engine"] = this;

        lua_open_library(plugins::Plugins::lua.state);

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

        m_logging.info("Plugins ready.");
    }

    void Engine::load()
    {
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
