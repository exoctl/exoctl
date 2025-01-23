#pragma once

#include <engine/configuration/configuration.hxx>
#include <engine/logging.hxx>
#include <engine/lua/lua.hxx>
#include <filesystem>
#include <memory>
#include <thread>

namespace engine
{
    namespace plugins
    {
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
            static void register_class_member(const std::string &p_class,
                                              const std::string &p_member_name,
                                              T &p_member)
            {
                lua::Lua::register_class_member(
                    p_class, p_member_name, p_member);
            }

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

            void run_plugins_thread();
        };
    } // namespace plugins
} // namespace engine
