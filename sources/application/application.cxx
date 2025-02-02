#include <application/application.hxx>
#include <engine/configuration/exception.hxx>
#include <engine/exception.hxx>
#include <engine/plugins/plugins.hxx>
#include <engine/version.hxx>

namespace application
{
    Application::Application(int argc, const char **argv)
        : m_argc(argc), m_argv(argv), m_config(config::ENGINE_CONFIG_PATH),
          m_log(m_config)
#ifdef PROTECT_ANTI_DEBUG
          ,
          m_debug()
#endif
    {
        TRY_BEGIN()
#ifdef PROTECT_ANTI_DEBUG
        m_debug.run();
#endif
        m_config.load();
        m_log.load();
        TRY_END()
        CATCH(engine::configuration::exception::Load, {
            fmt::print(stderr, "Failed to load configuration: {}\n", e.what());
            RETHROW();
        })

#ifdef ENGINE_PRO
#pragma message("Compiling with ENGINE_PRO: Skull PRO version")
        LOG(m_log, info, "Starting Skull PRO");
#else
#pragma message("Compiling without ENGINE_PRO: Skull FREE version")
        LOG(m_log, info, "Starting Skull FREE");
#endif
        m_engine = std::make_unique<engine::Engine>(m_config, m_log);
    }

    int Application::run()
    {
        LOG(m_log, debug, "Name        : {}", m_config.get_project().name);
        LOG(m_log, debug, "Version     : {}", m_config.get_project().version);
        LOG(m_log,
            debug,
            "Description : {}",
            m_config.get_project().description);
        LOG(m_log, debug, "Copyright   : {}", m_config.get_project().copyright);

        LOG(m_log,
            debug,
            "Mode        : {}",
#ifndef DEBUG
            "Release");
#else
            "Debug");
#endif

        LOG(m_log,
            info,
            "Running engine with configuration from '{}'...",
            m_config.get_path_config());

        TRY_BEGIN()
#ifdef ENGINE_PRO
        m_engine->register_plugins();
#endif
        m_engine->run();
        TRY_END()
        CATCH(engine::exception::Run, {
            LOG(m_log, error, "Engine encountered an error: {}", e.what());
            return EXIT_FAILURE;
        })

        LOG(m_log, info, "Engine stopped successfully.");
        return EXIT_SUCCESS;
    }
} // namespace application

int main(int argc, char *argv[])
{
    application::Application application(argc, (const char **) argv);
    return application.run();
}