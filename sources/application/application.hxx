#pragma once

#include <application/anti/debug/debug.hxx>
#include <engine/configuration/configuration.hxx>
#include <engine/engine.hxx>
#include <engine/interfaces/iplugins.hxx>
#include <engine/logging.hxx>
#include <memory>
#include <string>

namespace application
{
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

      private:
        int m_argc;
        const char **m_argv;

        engine::configuration::Configuration m_config;
        engine::logging::Logging m_log;
#ifdef PROTECT_ANTI_DEBUG
        anti::debug::Debug m_debug;
#endif
        std::unique_ptr<engine::Engine> m_engine;
    };
} // namespace application
