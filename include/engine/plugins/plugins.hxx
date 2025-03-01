#ifdef ENGINE_PRO

#pragma once

#include <engine/configuration/configuration.hxx>
#include <engine/logging/logging.hxx>
#include <engine/lua/lua.hxx>
#include <filesystem>
#include <functional>
#include <future>
#include <memory>

namespace engine
{
    namespace plugins
    {
        class Plugins
        {
          public:
            Plugins() = default;
            ~Plugins() = default;

            void setup(configuration::Configuration &, logging::Logging &);
            void load_plugin_buff(const std::string &);
            void load_plugin_file(const std::filesystem::path &);
            void load_plugins_folder(const std::string &);

            void load();
            std::future<void> run_async();

            static lua::Lua lua;

          private:
            configuration::Configuration m_config;
            logging::Logging m_log;

            void run_plugins_thread();
            void load_libraries();
        };
    } // namespace plugins
} // namespace engine

#endif