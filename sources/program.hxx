#pragma once

#include <engine/configuration/configuration.hxx>
#include <engine/engine.hxx>
#include <engine/logging.hxx>

namespace program
{
    namespace sections
    {
        using init_array = void (*)();
    }

    class Program
    {
      public:
        Program(int = 0, const char ** = nullptr);
        ~Program();
        int run();

      protected:
        friend struct ProgramEntry;
        static void init_array();

      private:
        const int m_argc;
        const char **m_argv;
        configuration::Configuration m_config;
        logging::Logging m_log;
        std::unique_ptr<engine::Engine> m_engine;
    };

    struct ProgramEntry {
        static void invoke()
        {
            Program::init_array();
        }
    };
} // namespace program