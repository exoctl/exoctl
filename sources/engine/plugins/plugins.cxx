#include <dirent.h>
#include <engine/memory/memory.hxx>
#include <engine/plugins/exception.hxx>
#include <engine/plugins/plugins.hxx>
#include <fmt/core.h>
#include <functional>
#include <future>
#include <sys/types.h>

namespace engine
{
    namespace plugins
    {
        lua::Lua Plugins::lua;
        configuration::Configuration Plugins::m_config;
        logging::Logging Plugins::m_log;

        void Plugins::setup(configuration::Configuration &p_config,
                            logging::Logging &p_log)
        {
            m_config = p_config;
            m_log = p_log;

            lua.state.set_panic(
                reinterpret_cast<lua_CFunction>(&Plugins::plugins_panic));

            if (!m_config.get("plugins.enable").value<bool>().value())
                m_log.warn("Plugins not enabled");
        }

        void Plugins::load_libraries()
        {
            if (m_config.get("plugins.enable").value<bool>().value()) {
                std::vector<std::string> libs_any;
                for (const auto &elem :
                     *m_config.get("plugins.lua.standard.libraries")
                          .as_array()) {
                    if (!elem.is_string()) {
                        throw exception::LoadPlugin(
                            "Array contains non-string elements at key: "
                            "plugins.lua.standard.libraries");
                    }
                    libs_any.push_back(*elem.value<std::string>());
                }

                m_log.info(fmt::format("Loading lua standard libraries: '{}'",
                                       fmt::join(libs_any, ", ")));

                for (const auto &name : libs_any) {
                    auto lib = lua.from_lib(name);
                    lua.state.open_libraries(lib);
                }
            }
        }

        void Plugins::load_plugin_buff(const std::string &)
        {
        }

        void Plugins::load_plugin_file(const std::filesystem::path &p_path)
        {
            if (p_path.extension() == ".lua") {

                m_log.info(
                    "Loading and creating environment for the plugin '{}'",
                    p_path.c_str());

                const engine::lua::Env env(
                    lua.state, sol::create, lua.state.globals());

                if (!lua.load_script_file(p_path.filename(), p_path, env)) {
                    m_log.error("Falied to load plugin '{}'", p_path.c_str());
                }
            }
        }

        void Plugins::load()
        {
            Plugins::load_libraries();
            if (m_config.get("plugins.enable").value<bool>().value()) {
                Plugins::load_plugins_folder(
                    m_config.get("plugins.path").value<std::string>().value());
            }
        }

        std::future<void> Plugins::run_async()
        {
            if (!m_config.get("plugins.enable").value<bool>().value()) {
                return std::future<void>();
            }

            m_log.info("Launching plugins async...");
            return std::async(
                std::launch::async, &Plugins::run_plugins_thread, this);
        }

        const int Plugins::plugins_panic(lua_State *state)
        {
            m_log.error(
                "Lua is in a panic state and will now abort() the application");

            if (state != nullptr) {
                const char *error_msg = lua_tostring(state, -1);
                m_log.error("Error message: '{}'",
                            error_msg ? error_msg : "Unknown error");

                lua_Debug ar;
                int level = 0;
                while (lua_getstack(state, level, &ar)) {
                    lua_getinfo(state, "Sln", &ar);
                    m_log.error("#{} -> {}:{} ({})",
                                level,
                                ar.short_src,
                                ar.currentline,
                                ar.name ? ar.name : "unknown");
                    level++;
                }
            }

            return 0;
        }

        void Plugins::run_plugins_thread()
        {
            lua.run();
        }

        void Plugins::load_plugins_folder(const std::string &p_path)
        {
            if (m_config.get("plugins.enable").value<bool>().value()) {
                DIR *dir = opendir(p_path.c_str());
                if (!dir)
                    throw plugins::exception::LoadPlugin(
                        fmt::format("{} : {}", strerror(errno), p_path));

                const struct dirent *entry;
                while (!IS_NULL((entry = readdir(dir)))) {
                    const std::filesystem::path entry_name = entry->d_name;
                    const std::string full_path = fmt::format(
                        "{}/{}", p_path.c_str(), entry_name.c_str());

                    if (entry_name == "." || entry_name == "..") {
                        continue;
                    } else if (entry->d_type == DT_DIR) {
                        Plugins::load_plugins_folder(full_path);
                    }

                    Plugins::load_plugin_file(full_path);
                }
                closedir(dir);
            }
        }
    } // namespace plugins
} // namespace engine