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
    {
        TRY_BEGIN()
        m_config.load();
        m_log.load();
        TRY_END()
        CATCH(engine::configuration::exception::Load, {
            fmt::print(stderr, "Failed to load configuration: {}\n", e.what());
            RETHROW();
        })

#ifndef ENGINE_PRO
        LOG(m_log, info, "Starting Skull PRO");
#else
        LOG(m_log, info, "Starting Skull");
#endif
        ENGINE_INSTANCE = std::make_unique<engine::Engine>(m_config, m_log);

        Application::register_plugins();
    }

    void Application::register_plugins()
    {
        int version = ENGINE_VERSION_CODE;
        std::function<std::any()> stop = [&]() -> std::any {
            ENGINE_INSTANCE.get()->stop();
            return {};
        };

        engine::plugins::Plugins::register_class("engine", &ENGINE_INSTANCE);
        engine::plugins::Plugins::register_class_member(
            "engine", "version_code", version);
        engine::plugins::Plugins::register_class_member(
            "engine", "is_running", ENGINE_INSTANCE.get()->is_running);
        engine::plugins::Plugins::register_class_method("engine", "stop", stop);
    }

    void Application::initialize_sections()
    {
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
        ENGINE_INSTANCE->run();
        TRY_END()
        CATCH(engine::exception::Run, {
            LOG(m_log, error, "Engine encountered an error: {}", e.what());
            return EXIT_FAILURE;
        })

        LOG(m_log, info, "Engine stopped successfully.");
        return EXIT_SUCCESS;
    }
} // namespace application

// section .init_array to implement DRM
[[gnu::section(".init_array")]] application::sections::init_array init =
    &application::ProgramEntry::invoke;
