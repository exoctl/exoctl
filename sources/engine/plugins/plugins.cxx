#ifdef ENGINE_PRO

#include <dirent.h>
#include <engine/memory/memory.hxx>
#include <engine/plugins/exception.hxx>
#include <engine/plugins/plugins.hxx>
#include <fmt/core.h>
#include <future>
#include <sys/types.h>

namespace engine
{
    namespace plugins
    {
        lua::Lua Plugins::lua;

        void Plugins::setup(configuration::Configuration &p_config,
                            logging::Logging &p_log)
        {
            m_config = p_config;
            m_log = p_log;

            if (!m_config.get_plugins().enable)
                LOG(m_log, warn, "Plugins not enabled");
        }

        void Plugins::load_plugin_buff(const std::string &)
        {
        }

        void Plugins::load_plugin_file(const std::filesystem::path &p_path)
        {
            if (p_path.extension() == ".lua") {
                LOG(m_log, info, "Loading plugin lua '{}'", p_path.c_str());
                if (!lua.load_script_file(p_path.filename(), p_path)) {
                    LOG(m_log,
                        error,
                        "Falied to load plugin '{}'",
                        p_path.c_str());
                }
            }
        }

        void Plugins::load()
        {
            if (m_config.get_plugins().enable) {
                Plugins::load_plugins_folder(m_config.get_plugins().path);
            }
        }

        void Plugins::run()
        {
            if (m_config.get_plugins().enable) {
                LOG(m_log, info, "Launching plugins async...");
                std::async(
                    std::launch::async, &Plugins::run_plugins_thread, this)
                    .get();
            }
        }

        void Plugins::run_plugins_thread()
        {
            lua.run();
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

#endif