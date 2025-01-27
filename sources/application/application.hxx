#pragma once

#include <engine/configuration/configuration.hxx>
#include <engine/engine.hxx>
#include <engine/logging.hxx>
#include <memory>
#include <string>


#define ENGINE_INSTANCE m_engine

namespace application
{
    namespace sections
    {
        using init_array = void (*)();
    } // namespace sections

    namespace config
    {
        inline constexpr const char *ENGINE_CONFIG_PATH =
            "config/engine/engine.conf";
    } // namespace config

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

        std::unique_ptr<engine::Engine> ENGINE_INSTANCE;
    };

    struct ProgramEntry {
        static void invoke()
        {
            Application::initialize_sections();
        }
    };
} // namespace application
