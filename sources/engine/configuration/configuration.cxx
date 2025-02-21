#include <engine/configuration/configuration.hxx>
#include <engine/configuration/entitys.hxx>
#include <engine/configuration/exception.hxx>
#include <engine/plugins/plugins.hxx>

namespace engine
{
    namespace configuration
    {
        void Configuration::bind_to_lua(sol::state_view &p_lua)
        {
            p_lua.new_usertype<configuration::Configuration>(
                "Configuration",
                sol::constructors<configuration::Configuration()>(),
                "load",
                &Configuration::load,
#ifdef ENGINE_PRO
                "register_plugins",
                &Configuration::register_plugins,
#endif
                "setup",
                Configuration::setup);
        }

        void Configuration::setup(const std::string &p_path)
        {
            m_path.assign(p_path);
            m_toml.parse_file(m_path);
        }

        void Configuration::load()
        {
            TRY_BEGIN()

            Configuration::load_project();
            Configuration::load_server();
            Configuration::load_yara();
            Configuration::load_logging();
            Configuration::load_av_clamav();
            Configuration::load_lief();
            Configuration::load_llama();
            Configuration::load_decompiler();

#ifdef ENGINE_PRO
            Configuration::load_plugins();
#endif

            TRY_END()
            CATCH(toml::parse_error, {
                const auto &source = e.source();
                throw exception::Load(fmt::format(
                    "Error parsing file '{:s}' at line {:d}, column {:d}: {:s}",
                    *source.path,
                    source.begin.line,
                    source.begin.column,
                    e.description()));
            })
            CATCH(std::exception, {
                throw exception::Load(
                    fmt::format("Unexpected error: {:s}", e.what()));
            });
        }

#ifdef ENGINE_PRO
        void Configuration::register_plugins()
        {
            plugins::Plugins::lua.state.new_usertype<configuration::DynConfig>(
                "DynConfig",
                "setup",
                &configuration::Configuration::setup,
                "load_logging",
                Configuration::load_logging,
                "load",
                &DynConfig::load,
                "get",
                sol::overload([](configuration::DynConfig &self,
                                 const std::string &section,
                                 const int type) -> sol::object {
                    auto &lua = plugins::Plugins::lua.state;
                    switch (type) {
                        case 1:
                            return sol::make_object(
                                lua, self.get<std::string>(section));
                        case 2:
                            return sol::make_object(lua,
                                                    self.get<int64_t>(section));
                        case 3:
                            return sol::make_object(lua,
                                                    self.get<bool>(section));
                        case 4: {
                            // Obtenha o vetor de std::any
                            auto vec = self.get<std::vector<std::any>>(section);
                            // Cria uma nova tabela Lua
                            sol::table luaTable = lua.create_table();
                            // Itera sobre cada elemento do vetor
                            for (size_t i = 0; i < vec.size(); ++i) {
                                const auto &elem = vec[i];
                                if (elem.type() == typeid(std::string)) {
                                    luaTable[i + 1] =
                                        std::any_cast<std::string>(elem);
                                } else if (elem.type() == typeid(int64_t)) {
                                    luaTable[i + 1] =
                                        std::any_cast<int64_t>(elem);
                                } else if (elem.type() == typeid(bool)) {
                                    luaTable[i + 1] = std::any_cast<bool>(elem);
                                } else {
                                    luaTable[i + 1] = sol::nil;
                                }
                            }
                            return sol::make_object(lua, luaTable);
                        }
                        default:
                            throw std::runtime_error("Tipo não suportado");
                    }
                }));
        }
#endif

        void DynConfig::load()
        {
            dynamic_configs.clear();

            std::function<void(const toml::table &,
                               std::unordered_map<std::string, std::any> &)>
                process_table;
            process_table =
                [&process_table](
                    const toml::table &table,
                    std::unordered_map<std::string, std::any> &section_data) {
                    for (const auto &[key, value] : table) {
                        std::string key_str = std::string(key);
                        if (value.is_string()) {
                            section_data[key_str] = value.as_string()->get();
                        } else if (value.is_integer()) {
                            section_data[key_str] = value.as_integer()->get();
                        } else if (value.is_boolean()) {
                            section_data[key_str] = value.as_boolean()->get();
                        } else if (value.is_floating_point()) {
                            section_data[key_str] =
                                value.as_floating_point()->get();
                        } else if (value.is_array()) {
                            std::vector<std::any> array_values;
                            for (const auto &elem : *value.as_array()) {
                                if (elem.is_string()) {
                                    array_values.push_back(
                                        elem.as_string()->get());
                                } else if (elem.is_integer()) {
                                    array_values.push_back(
                                        elem.as_integer()->get());
                                } else if (elem.is_floating_point()) {
                                    array_values.push_back(
                                        elem.as_floating_point()->get());
                                } else if (elem.is_boolean()) {
                                    array_values.push_back(
                                        elem.as_boolean()->get());
                                }
                            }
                            section_data[key_str] = array_values;
                        } else if (value.is_table()) {
                            std::unordered_map<std::string, std::any>
                                sub_section_data;
                            process_table(*value.as_table(), sub_section_data);
                            section_data[key_str] = sub_section_data;
                        }
                    }
                };

            process_table(m_toml.tbl, dynamic_configs);
        }

        Configuration &Configuration::operator=(const Configuration &p_config)
        {
            if (this != &p_config) {
                m_path = m_path;

                m_toml = p_config.m_toml;
                lief = p_config.lief;
                llama = p_config.llama;
                av_clamav = p_config.av_clamav;
                project = p_config.project;
                yara = p_config.yara;
                logging = p_config.logging;
                server = p_config.server;
                decompiler = p_config.decompiler;

#ifdef ENGINE_PRO
                plugins = p_config.plugins;
#endif
            }
            return *this;
        }

#ifdef ENGINE_PRO
        void Configuration::load_plugins()
        {
            plugins = record::plugins::Plugins{
                .path =
                    m_toml.tbl["plugins"]["path"].value<std::string>().value(),
                .enable = m_toml.tbl["plugins"]["enable"].value<bool>().value(),
                .lua = (record::plugins::lua::Lua) {
                    .standard =
                        (record::plugins::lua::Standard) {.libraries = [&] {
                            std::vector<std::string> lib_vec;
                            if (auto arr = m_toml
                                               .tbl["plugins"]["lua"]
                                                   ["standard"]["libraries"]
                                               .as_array()) {
                                for (const auto &val : *arr) {
                                    if (val.is_string()) {
                                        lib_vec.emplace_back(
                                            val.as_string()->get());
                                    }
                                }
                            }
                            return lib_vec;
                        }()}}};
        }
#endif
        void Configuration::load_av_clamav()
        {
            av_clamav = (record::av::clamav::Clamav) {
                .database =
                    {.default_path =
                         m_toml.tbl["av"]["clamav"]["database"]["default_path"]
                             .value<std::string>()
                             .value()},
                .log = {.level = m_toml.tbl["av"]["clamav"]["_"]["log"]["level"]
                                     .value<unsigned int>()
                                     .value(),
                        .name = m_toml.tbl["av"]["clamav"]["_"]["log"]["name"]
                                    .value<std::string>()
                                    .value()}};
        }

        void Configuration::load_decompiler()
        {
            decompiler = (record::decompiler::Decompiler) {
                .llama = {.model = m_toml.tbl["decompiler"]["llama"]["model"]
                                       .value<std::string>()
                                       .value()}};
        }

        void Configuration::load_project()
        {
            project = (record::Project) {
                .name =
                    m_toml.tbl["project"]["name"].value<std::string>().value(),
                .version = m_toml.tbl["project"]["version"]
                               .value<std::string>()
                               .value(),
                .description = m_toml.tbl["project"]["description"]
                                   .value<std::string>()
                                   .value(),
                .copyright = m_toml.tbl["project"]["copyright"]
                                 .value<std::string>()
                                 .value()};
        }

        void Configuration::load_server()
        {
            server = (record::server::Server) {
                .log = {.level = m_toml.tbl["server"]["_"]["log"]["level"]
                                     .value<unsigned int>()
                                     .value(),
                        .name = m_toml.tbl["server"]["_"]["log"]["name"]
                                    .value<std::string>()
                                    .value()},
                .name =
                    m_toml.tbl["server"]["name"].value<std::string>().value(),
                .bindaddr = m_toml.tbl["server"]["bindaddr"]
                                .value<std::string>()
                                .value(),
                .port = m_toml.tbl["server"]["port"]
                            .value<unsigned short>()
                            .value(),
                .threads = m_toml.tbl["server"]["threads"]
                               .value<unsigned short>()
                               .value(),
                .ssl_certificate_path =
                    m_toml.tbl["server"]["ssl_certificate_path"]
                        .value<std::string>()
                        .value(),
            };
        }

        void Configuration::load_yara()
        {
            yara = (record::yara::Yara) {
                .rules = {.path = m_toml.tbl["yara"]["rules"]["path"]
                                      .value<std::string>()
                                      .value()}};
        } // namespace engine

        void Configuration::load_logging()
        {
            logging = (record::logging::Logging) {
                .filepath = m_toml.tbl["logging"]["filepath"]
                                .value<std::string>()
                                .value(),
                .name =
                    m_toml.tbl["logging"]["name"].value<std::string>().value(),
                .pattern = m_toml.tbl["logging"]["pattern"]
                               .value<std::string>()
                               .value(),
                .type =
                    m_toml.tbl["logging"]["type"].value<std::string>().value(),
                .console = m_toml.tbl["logging"]["console"]["output_enabled"]
                               .value<bool>()
                               .value(),
                .level = m_toml.tbl["logging"]["level"]
                             .value<unsigned int>()
                             .value(),
                .trace = {.interval =
                              m_toml.tbl["logging"]["trace_updates"]["interval"]
                                  .value<uint16_t>()
                                  .value()},
                .daily_settings =
                    {.hours = m_toml.tbl["logging"]["daily"]["hours"]
                                  .value<uint16_t>()
                                  .value(),
                     .minutes = m_toml.tbl["logging"]["daily"]["minutes"]
                                    .value<uint16_t>()
                                    .value(),
                     .max_size = m_toml.tbl["logging"]["daily"]["max_size"]
                                     .value<uint16_t>()
                                     .value()},
                .rotation_settings = {
                    .max_files = m_toml.tbl["logging"]["rotation"]["max_files"]
                                     .value<uint16_t>()
                                     .value(),
                    .max_size = m_toml.tbl["logging"]["rotation"]["max_size"]
                                    .value<uint16_t>()
                                    .value()}};
        }

        void Configuration::load_lief()
        {
            lief = (record::lief::Lief) {
                .log{.level = m_toml.tbl["lief"]["_"]["log"]["level"]
                                  .value<unsigned int>()
                                  .value(),
                     .name = m_toml.tbl["lief"]["_"]["log"]["name"]
                                 .value<std::string>()
                                 .value()}};
        }

        void Configuration::load_llama()
        {
            llama = (record::llama::Llama) {
                .log{.level = m_toml.tbl["llama"]["_"]["log"]["level"]
                                  .value<unsigned int>()
                                  .value(),
                     .name = m_toml.tbl["llama"]["_"]["log"]["name"]
                                 .value<std::string>()
                                 .value()}};
        }

    } // namespace configuration
} // namespace engine