#ifdef ENGINE_PRO

#pragma once

#include <engine/configuration/configuration.hxx>
#include <engine/logging.hxx>
#include <engine/lua/lua.hxx>
#include <filesystem>
#include <functional>
#include <memory>

namespace engine
{
    namespace plugins
    {
        class Plugins
        {
          public:
            Plugins(configuration::Configuration &, logging::Logging &);
            ~Plugins() = default;

            void load_plugin_buff(const std::string &);
            void load_plugin_file(const std::filesystem::path &);
            void load_plugins_folder(const std::string &);

            void load();
            void run();

            lua::Lua lua;

          private:
            configuration::Configuration &m_config;
            logging::Logging &m_log;

            void run_plugins_thread();
        };
    } // namespace plugins
} // namespace engine

#endif