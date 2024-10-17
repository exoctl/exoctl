#include <engine/configuration/exception.hxx>
#include <engine/exception.hxx>
#include <program/program.hxx>

namespace program
{
    Program::Program(int p_argc, const char **p_argv)
        : m_argc(p_argc), m_argv(p_argv), m_config("config/engine.conf"),
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

        m_engine = std::make_unique<engine::Engine>(m_config, m_log);
    }

    Program::~Program()
    {
    }

    void Program::init_array()
    {
    }

    const int Program::run()
    {
        LOG(m_log, info, "Name        : {}", m_config.get_project().name);
        LOG(m_log, info, "Version     : {}", m_config.get_project().version);
        LOG(m_log,
            info,
            "Description : {}",
            m_config.get_project().description);
        LOG(m_log, info, "Copyright   : {}", m_config.get_project().copyright);
        LOG(m_log,
            info,
            "Mode        : {}",
#if DEBUG
            "Debug");
#else
            "Release");
#endif

        LOG(m_log,
            info,
            "Running engine with configuration from '{}'...",
            m_config.get_path_config());

        TRY_BEGIN()
        LOG(m_log, info, "Starting engine...");
        m_engine->run();
        LOG(m_log, info, "Engine stopped successfully.");

        TRY_END()
        CATCH(engine::exception::Run, {
            LOG(m_log, error, "Engine encountered an error: {}", e.what());
            return EXIT_FAILURE;
        })

        LOG(m_log, info, "Exiting program.");
        return EXIT_SUCCESS;
    }
} // namespace program

// section .init_array for implement DRM
[[gnu::section(".init_array")]] program::sections::init_array init =
    &program::ProgramEntry::invoke;