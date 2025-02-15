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
                "lief",
                sol::readonly(&Configuration::lief),
                "llama",
                sol::readonly(&Configuration::llama),
                "av_clamav",
                sol::readonly(&Configuration::av_clamav),
                "project",
                sol::readonly(&Configuration::project),
                "yara",
                sol::readonly(&Configuration::yara),
                "logging",
                sol::readonly(&Configuration::logging),
                "server",
                sol::readonly(&Configuration::server),
                "decompiler",
                sol::readonly(&Configuration::decompiler),
                "plugins",
                sol::readonly(&Configuration::plugins),
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
            plugins::Plugins::lua.state["_configuration"] = this;

            plugins::Plugins::lua.state
                .new_usertype<configuration::Configuration>(
                    "Configuration",
                    "setup",
                    &configuration::Configuration::setup,
                    "load_logging",
                    Configuration::load_logging,
                    "lief",
                    sol::readonly(&Configuration::lief),
                    "llama",
                    sol::readonly(&Configuration::llama),
                    "av_clamav",
                    sol::readonly(&Configuration::av_clamav),
                    "project",
                    sol::readonly(&Configuration::project),
                    "yara",
                    sol::readonly(&Configuration::yara),
                    "logging",
                    sol::readonly(&Configuration::logging),
                    "server",
                    sol::readonly(&Configuration::server),
                    "decompiler",
                    sol::readonly(&Configuration::decompiler),
                    "plugins",
                    sol::readonly(&Configuration::plugins),
                    "load",
                    &Configuration::load);
        }
#endif

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
                .path = m_toml.get_tbl()["plugins"]["path"]
                            .value<std::string>()
                            .value(),
                .enable =
                    m_toml.get_tbl()["plugins"]["enable"].value<bool>().value(),
                .lua = (record::plugins::lua::Lua) {
                    .standard =
                        (record::plugins::lua::Standard) {.libraries = [&] {
                            std::vector<std::string> lib_vec;
                            if (auto arr =
                                    m_toml
                                        .get_tbl()["plugins"]["lua"]["standard"]
                                                  ["libraries"]
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
                .database = {.default_path =
                                 m_toml
                                     .get_tbl()["av"]["clamav"]["database"]
                                               ["default_path"]
                                     .value<std::string>()
                                     .value()},
                .log = {
                    .level =
                        m_toml.get_tbl()["av"]["clamav"]["_"]["log"]["level"]
                            .value<int>()
                            .value(),
                    .name = m_toml.get_tbl()["av"]["clamav"]["_"]["log"]["name"]
                                .value<std::string>()
                                .value()}};
        }

        void Configuration::load_decompiler()
        {
            decompiler = (record::decompiler::Decompiler) {
                .llama = {.model =
                              m_toml.get_tbl()["decompiler"]["llama"]["model"]
                                  .value<std::string>()
                                  .value()}};
        }

        void Configuration::load_project()
        {
            project = (record::Project) {
                .name = m_toml.get_tbl()["project"]["name"]
                            .value<std::string>()
                            .value(),
                .version = m_toml.get_tbl()["project"]["version"]
                               .value<std::string>()
                               .value(),
                .description = m_toml.get_tbl()["project"]["description"]
                                   .value<std::string>()
                                   .value(),
                .copyright = m_toml.get_tbl()["project"]["copyright"]
                                 .value<std::string>()
                                 .value()};
        }

        void Configuration::load_server()
        {
            server = (record::server::Server) {
                .log = {.level = m_toml.get_tbl()["server"]["_"]["log"]["level"]
                                     .value<int>()
                                     .value(),
                        .name = m_toml.get_tbl()["server"]["_"]["log"]["name"]
                                    .value<std::string>()
                                    .value()},
                .name = m_toml.get_tbl()["server"]["name"]
                            .value<std::string>()
                            .value(),
                .bindaddr = m_toml.get_tbl()["server"]["bindaddr"]
                                .value<std::string>()
                                .value(),
                .port = m_toml.get_tbl()["server"]["port"]
                            .value<unsigned short>()
                            .value(),
                .threads = m_toml.get_tbl()["server"]["threads"]
                               .value<unsigned short>()
                               .value(),
                .ssl_certificate_path =
                    m_toml.get_tbl()["server"]["ssl_certificate_path"]
                        .value<std::string>()
                        .value(),
            };
        }

        void Configuration::load_yara()
        {
            yara = (record::yara::Yara) {
                .rules = {.path = m_toml.get_tbl()["yara"]["rules"]["path"]
                                      .value<std::string>()
                                      .value()}};
        } // namespace engine

        void Configuration::load_logging()
        {
            logging = (record::logging::Logging) {
                .filepath = m_toml.get_tbl()["logging"]["filepath"]
                                .value<std::string>()
                                .value(),
                .name = m_toml.get_tbl()["logging"]["name"]
                            .value<std::string>()
                            .value(),
                .pattern = m_toml.get_tbl()["logging"]["pattern"]
                               .value<std::string>()
                               .value(),
                .type = m_toml.get_tbl()["logging"]["type"]
                            .value<std::string>()
                            .value(),
                .console =
                    m_toml.get_tbl()["logging"]["console"]["output_enabled"]
                        .value<bool>()
                        .value(),
                .level =
                    m_toml.get_tbl()["logging"]["level"].value<int>().value(),
                .trace = {.interval = m_toml
                                          .get_tbl()["logging"]["trace_updates"]
                                                    ["interval"]
                                          .value<uint16_t>()
                                          .value()},
                .daily_settings =
                    {.hours = m_toml.get_tbl()["logging"]["daily"]["hours"]
                                  .value<uint16_t>()
                                  .value(),
                     .minutes = m_toml.get_tbl()["logging"]["daily"]["minutes"]
                                    .value<uint16_t>()
                                    .value(),
                     .max_size =
                         m_toml.get_tbl()["logging"]["daily"]["max_size"]
                             .value<uint16_t>()
                             .value()},
                .rotation_settings = {
                    .max_files =
                        m_toml.get_tbl()["logging"]["rotation"]["max_files"]
                            .value<uint16_t>()
                            .value(),
                    .max_size =
                        m_toml.get_tbl()["logging"]["rotation"]["max_size"]
                            .value<uint16_t>()
                            .value()}};
        }

        void Configuration::load_lief()
        {
            lief = (record::lief::Lief) {
                .log{.level = m_toml.get_tbl()["lief"]["_"]["log"]["level"]
                                  .value<int>()
                                  .value(),
                     .name = m_toml.get_tbl()["lief"]["_"]["log"]["name"]
                                 .value<std::string>()
                                 .value()}};
        }

        void Configuration::load_llama()
        {
            llama = (record::llama::Llama) {
                .log{.level = m_toml.get_tbl()["llama"]["_"]["log"]["level"]
                                  .value<int>()
                                  .value(),
                     .name = m_toml.get_tbl()["llama"]["_"]["log"]["name"]
                                 .value<std::string>()
                                 .value()}};
        }

    } // namespace configuration
} // namespace engine