#pragma once

#include <engine/configuration/configuration.hxx>
#include <engine/lua/lua.hxx>
#include <engine/logging.hxx>
#include <engine/plugins/exception.hxx>
#include <filesystem>
#include <memory>

namespace engine
{
    namespace plugins
    {
        // TODO: improve the plugin manager so it becomes async
        class Plugins
        {
          public:
            Plugins(configuration::Configuration &, logging::Logging &);
            ~Plugins();

            void load_plugin_buff(const std::string &);
            void load_plugin_file(const std::filesystem::path &);
            void load_plugins_folder(const std::string &);

            template <typename T>
            static void register_t_global(const std::string &, T &);

            template <typename T>
            static void register_class_method(const std::string &,
                                              const std::string &,
                                              void (T::*)());

            template <typename T>
            static void register_class_member(const std::string &,
                                              const std::string &,
                                              T &);

            template <typename T>
            static void register_class(const std::string &p_class, T *p_ptr)
            {
                lua::Lua::register_class(p_class, p_ptr);
            }

            template <typename T>
            static void register_class(const std::string &p_class,
                                       std::unique_ptr<T> &p_ptr)
            {
                lua::Lua::register_class(p_class, p_ptr);
            }

            void finalize();
            void load();
            void run();

          private:
            configuration::Configuration &m_config;
            logging::Logging &m_log;

            lua::Lua m_lua;
        };
    } // namespace plugins
} // namespace engine