#include <engine/configuration/exception.hxx>
#include <engine/exception.hxx>
#include <program/program.hxx>


namespace program
{
    Program::Program(int p_argc, const char **p_argv)
        : m_argc(p_argc), m_argv(p_argv), m_config(config::config_engine),
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

        LOG(m_log, info, "Starting engine ...");
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
        {
            LOG(m_log, debug, "Name        : {}", m_config.get_project().name);
            LOG(m_log,
                debug,
                "Version     : {}",
                m_config.get_project().version);
            LOG(m_log,
                debug,
                "Description : {}",
                m_config.get_project().description);
            LOG(m_log,
                debug,
                "Copyright   : {}",
                m_config.get_project().copyright);
            LOG(m_log,
                debug,
                "Mode        : {}",
#if DEBUG
                "Debug");
#else
                "Release");
#endif
        }
        
        LOG(m_log,
            info,
            "Running engine with configuration from '{}'...",
            m_config.get_path_config());

        TRY_BEGIN()
        m_engine->run();
        TRY_END()
        CATCH(engine::exception::Run, {
            LOG(m_log, error, "Engine encountered an error: {}", e.what());
            return EXIT_FAILURE;
        })

        LOG(m_log, info, "Engine stopped successfully.");
        return EXIT_SUCCESS;
    }
} // namespace program

// section .init_array for implement DRM
[[gnu::section(".init_array")]] program::sections::init_array init =
    &program::ProgramEntry::invoke;
