#include "engine/configuration/entitys.hxx"
#include <engine/configuration/configuration.hxx>
#include <engine/configuration/exception.hxx>

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
                "path",
                &Configuration::path);
        }

        void Configuration::load()
        {
            TRY_BEGIN()
            m_toml.parse_file(path);
            Configuration::load_project();
            Configuration::load_server();
            Configuration::load_yara();
            Configuration::load_sig();
            Configuration::load_cache();
            Configuration::load_logging();
            Configuration::load_av_clamav();
            Configuration::load_lief();
            Configuration::load_llama();
            Configuration::load_decompiler();
#ifdef ENGINE_PRO
            Configuration::load_plugins();
#endif
            TRY_END()
            CATCH(std::exception, { throw exception::Load(e.what()); });
        }

        Configuration &Configuration::operator=(const Configuration &p_config)
        {
            if (this != &p_config) {
                path = path;

                m_toml = p_config.m_toml;
                m_cache = p_config.m_cache;
                m_lief = p_config.m_lief;
                m_llama = p_config.m_llama;
                m_av_clamav = p_config.m_av_clamav;
                m_project = p_config.m_project;
                m_yara = p_config.m_yara;
                m_logging = p_config.m_logging;
                m_sig = p_config.m_sig;
                m_server = p_config.m_server;
                m_decompiler = p_config.m_decompiler;

#ifdef ENGINE_PRO
                m_plugins = p_config.m_plugins;
#endif
            }
            return *this;
        }

        const record::cache::Cache &Configuration::get_cache() const
        {
            return m_cache;
        }

        const record::av::clamav::Clamav &Configuration::get_av_clamav() const
        {
            return m_av_clamav;
        }

        const record::Project &Configuration::get_project() const
        {
            return m_project;
        }

        const record::yara::Yara &Configuration::get_yara() const
        {
            return m_yara;
        }

        const record::logging::Logging &Configuration::get_logging() const
        {
            return m_logging;
        }

        const record::sig::Sig &Configuration::get_sig() const
        {
            return m_sig;
        }

        const record::server::Server &Configuration::get_server() const
        {
            return m_server;
        }

        const record::lief::Lief &Configuration::get_lief() const
        {
            return m_lief;
        }

        const record::llama::Llama &Configuration::get_llama() const
        {
            return m_llama;
        }

        const record::decompiler::Decompiler &Configuration::get_decompiler()
        {
            return m_decompiler;
        }

#ifdef ENGINE_PRO
        const record::plugins::Plugins &Configuration::get_plugins()
        {
            return m_plugins;
        }

        void Configuration::load_plugins()
        {
            m_plugins = (record::plugins::Plugins) {
                .path = m_toml.get_tbl()["plugins"]["path"]
                            .value<std::string>()
                            .value(),
                .enable = m_toml.get_tbl()["plugins"]["enable"]
                              .value<bool>()
                              .value()};
        }
#endif
        void Configuration::load_cache()
        {
            m_cache = (record::cache::Cache) {
                .type = m_toml.get_tbl()["cache"]["type"]
                            .value<std::string>()
                            .value(),
                .path = m_toml.get_tbl()["cache"]["path"]
                            .value<std::string>()
                            .value()};
        }

        void Configuration::load_av_clamav()
        {
            m_av_clamav = (record::av::clamav::Clamav) {
                .database = {.default_path =
                                 m_toml
                                     .get_tbl()["av"]["clamav"]["database"]
                                               ["default_path"]
                                     .value<std::string>()
                                     .value()}};
        }

        void Configuration::load_decompiler()
        {
            m_decompiler = (record::decompiler::Decompiler) {
                .llama = {.model =
                              m_toml.get_tbl()["decompiler"]["llama"]["model"]
                                  .value<std::string>()
                                  .value()}};
        }

        void Configuration::load_project()
        {
            m_project = (record::Project) {
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

        void Configuration::load_sig()
        {
            m_sig = (record::sig::Sig) {
                .rules = {.packed_path =
                              m_toml.get_tbl()["sig"]["rules"]["packed_path"]
                                  .value<std::string>()
                                  .value()}};
        }

        void Configuration::load_server()
        {
            m_server = (record::server::Server) {
                .log = {.level = m_toml.get_tbl()["server"]["_"]["log"]["level"]
                                     .value<int>()
                                     .value(),
                        .name = m_toml.get_tbl()["server"]["_"]["log"]["name"]
                                    .value<std::string>()
                                    .value()},
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
            m_yara = (record::yara::Yara) {
                .rules = {.malware_path =
                              m_toml.get_tbl()["yara"]["rules"]["malware_path"]
                                  .value<std::string>()
                                  .value(),
                          .packed_path =
                              m_toml.get_tbl()["yara"]["rules"]["packed_path"]
                                  .value<std::string>()
                                  .value(),
                          .cve_path =
                              m_toml.get_tbl()["yara"]["rules"]["cve_path"]
                                  .value<std::string>()
                                  .value()}};
        }

        void Configuration::load_logging()
        {
            m_logging = (record::logging::Logging) {
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
            m_lief = (record::lief::Lief) {
                .log{.level = m_toml.get_tbl()["lief"]["_"]["log"]["level"]
                                  .value<int>()
                                  .value(),
                     .name = m_toml.get_tbl()["lief"]["_"]["log"]["name"]
                                 .value<std::string>()
                                 .value()}};
        }

        void Configuration::load_llama()
        {
            m_llama = (record::llama::Llama) {
                .log{.level = m_toml.get_tbl()["llama"]["_"]["log"]["level"]
                                  .value<int>()
                                  .value(),
                     .name = m_toml.get_tbl()["llama"]["_"]["log"]["name"]
                                 .value<std::string>()
                                 .value()}};
        }

    } // namespace configuration
} // namespace engine