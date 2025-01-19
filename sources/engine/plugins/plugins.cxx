#include <dirent.h>
#include <engine/memory/memory.hxx>
#include <engine/plugins/plugins.hxx>
#include <fmt/core.h>
#include <sys/types.h>

namespace engine
{
    namespace plugins
    {
        Plugins::Plugins(configuration::Configuration &p_config,
                         logging::Logging &p_log)
            : m_config(p_config), m_log(p_log), m_lua()
        {
            if (!m_config.get_plugins().enable)
                LOG(m_log, warn, "Plugins not enabled");
        }

        Plugins::~Plugins()
        {
        }

        template <>
        void Plugins::register_class_member<bool>(
            const std::string &p_class_name,
            const std::string &p_member_name,
            bool &p_member)
        {
            lua::Lua::register_class_member(
                p_class_name, p_member_name, p_member);
        }

        template <>
        void Plugins::register_class_member<unsigned short>(
            const std::string &p_class_name,
            const std::string &p_member_name,
            unsigned short &p_member)
        {
            lua::Lua::register_class_member(
                p_class_name, p_member_name, p_member);
        }

        template <>
        void Plugins::register_class_member<std::string>(
            const std::string &p_class_name,
            const std::string &p_member_name,
            std::string &p_member)
        {
            lua::Lua::register_class_member(
                p_class_name, p_member_name, p_member);
        }

        template <>
        void Plugins::register_class_member<int>(
            const std::string &p_class_name,
            const std::string &p_member_name,
            int &p_member)
        {
            lua::Lua::register_class_member(
                p_class_name, p_member_name, p_member);
        }

        template <>
        void Plugins::register_t_global<int>(const std::string &p_name,
                                             int &p_value)
        {
            lua::Lua::register_global(p_name, p_value);
        }

        template <>
        void Plugins::register_t_global<std::string>(const std::string &p_name,
                                                     std::string &p_value)
        {
            lua::Lua::register_global(p_name, p_value);
        }

        template <>
        void Plugins::register_t_global<bool>(const std::string &p_name,
                                              bool &p_value)
        {
            lua::Lua::register_global(p_name, p_value);
        }

        void Plugins::load_plugin_buff(const std::string &)
        {
        }

        void Plugins::load_plugin_file(const std::filesystem::path &p_path)
        {
            if (p_path.extension() == ".lua") {
                LOG(m_log, info, "Loading plugin lua '{}'", p_path.c_str());
                m_lua.load_script_file(p_path.filename(), p_path);
            }
        }

        void Plugins::load()
        {
            if (m_config.get_plugins().enable) {
                Plugins::load_plugins_folder(m_config.get_plugins().path);
            }
        }

        void Plugins::finalize()
        {
            for (const auto &[script_name, script_path] : m_lua.get_scripts()) {
                m_lua.call_function(script_name, "_finalize");
            }
        }

        void Plugins::run()
        {
            if (m_config.get_plugins().enable) {
                LOG(m_log, info, "Running all plugins ...");
                m_lua.run();
            }
        }

        void Plugins::load_plugins_folder(const std::string &p_path)
        {
            DIR *dir = opendir(p_path.c_str());
            if (!dir)
                throw plugins::exception::LoadPlugin(strerror(errno));

            const struct dirent *entry;
            while (!IS_NULL((entry = readdir(dir)))) {
                const std::filesystem::path entry_name = entry->d_name;
                const std::string full_path =
                    fmt::format("{}/{}", p_path.c_str(), entry_name.c_str());

                if (entry_name == "." || entry_name == "..") {
                    continue;
                } else if (entry->d_type == DT_DIR) {
                    Plugins::load_plugins_folder(full_path);
                }

                Plugins::load_plugin_file(full_path);
            }
            closedir(dir);
        }
    } // namespace plugins
} // namespace engine
