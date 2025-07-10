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
        logging = p_log;
        configuration = p_config;

        database.setup(configuration, logging);
        server.setup(configuration, logging);
        plugins.setup(configuration, logging);
        m_clamav_log.setup(configuration, logging);
        m_llama_log.setup(configuration, logging);
        m_lief_log.setup(configuration, logging);
        m_server_log.setup(configuration, logging);
        bridge.setup(server);

        _plugins();
    }

    void Engine::_plugins()
    {
        logging.info("Engine registering plugins...");

        plugins::Plugins::lua.state.new_usertype<engine::Engine>(
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
            &Engine::logging,
            "configuration",
            &Engine::configuration,
            "server",
            &Engine::server,
            "version",
            &Engine::version,
            "database",
            &Engine::database);

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
        database.load();
        server.load();
        bridge.load();
        plugins.load();
    }

    void Engine::stop()
    {
        is_running = false;
        server.stop();
    }

    void Engine::run()
    {
        is_running = true;
        plugins.run_async();
        server.run_async();
    }
} // namespace engine
