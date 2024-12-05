#pragma once

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
      static inline std::string config_engine = "config/engine/engine.conf";  
    }

    class Application
    {
      public:
        Application(int = 0, const char ** = nullptr);
        ~Application();
        [[nodiscard]] const int run();

      protected:
        friend struct ProgramEntry;
        static void init_array();

      private:
        const int m_argc;
        const char **m_argv;
        engine::configuration::Configuration m_config;
        engine::logging::Logging m_log;
        std::unique_ptr<engine::Engine> m_engine;
    };

    struct ProgramEntry {
        static void invoke()
        {
            Application::init_array();
        }
    };
} // namespace application
