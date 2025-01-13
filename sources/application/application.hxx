#pragma once

#include <memory>
#include <string>
#include <engine/configuration/configuration.hxx>
#include <engine/engine.hxx>
#include <engine/logging.hxx>

namespace application
{
    namespace sections
    {
        using init_array = void (*)();
    }

    namespace config
    {
        inline constexpr const char *ENGINE_CONFIG_PATH = "config/engine/engine.conf";
    }

    class Application
    {
    public:
        explicit Application(int argc = 0, const char **argv = nullptr);
        ~Application() = default;

        [[nodiscard]] int run();

    protected:
        friend struct ProgramEntry;
        static void initialize_sections();

    private:
        int m_argc;
        const char **m_argv;
        engine::configuration::Configuration m_config;
        engine::logging::Logging m_log;
        std::unique_ptr<engine::Engine> m_engine;
    };

    struct ProgramEntry
    {
        static void invoke()
        {
            Application::initialize_sections();
        }
    };
} // namespace application
