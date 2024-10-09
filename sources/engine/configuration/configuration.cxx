#include <engine/configuration/configuration.hxx>

namespace configuration
{
    Configuration::Configuration(const std::string p_config)
        : m_path_config(p_config)
    {
        m_toml.parse_file(m_path_config);
    }

    void Configuration::load()
    {
        load_project();
        load_crowapp();
        load_yara();
        load_sig();
        load_cache();
        load_log();
        load_clamav();
    }

    Configuration::~Configuration()
    {
    }

    const std::string &Configuration::get_path_config() const
    {
        return m_path_config;
    }

    const record::cache::Cache &Configuration::get_cache() const
    {
        return m_cache;
    }

    const record::clamav::Clamav &Configuration::get_clamav() const
    {
        return m_clamav;
    }

    const record::Project &Configuration::get_project() const
    {
        return m_project;
    }

    const record::yara::Yara &Configuration::get_yara() const
    {
        return m_yara;
    }

    const record::log::Log &Configuration::get_log() const
    {
        return m_log;
    }

    const record::sig::Sig &Configuration::get_sig() const
    {
        return m_sig;
    }

    const record::crowapp::CrowApp &Configuration::get_crowapp() const
    {
        return m_crowapp;
    }

    void Configuration::load_cache()
    {
        m_cache = (record::cache::Cache){
            .type =
                m_toml.get_tbl()["cache"]["type"].value<std::string>().value(),
            .path =
                m_toml.get_tbl()["cache"]["path"].value<std::string>().value()};
    }

    void Configuration::load_clamav()
    {
        m_clamav = (record::clamav::Clamav){
            .database = {
                .default_path =
                    m_toml.get_tbl()["clamav"]["database"]["default_path"]
                        .value<std::string>()
                        .value()}};
    }

    void Configuration::load_project()
    {
        m_project = (record::Project){
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
        m_sig = (record::sig::Sig){
            .rules = {.packed_path =
                          m_toml.get_tbl()["sig"]["rules"]["packed_path"]
                              .value<std::string>()
                              .value()}};
    }

    void Configuration::load_crowapp()
    {
        m_crowapp = (record::crowapp::CrowApp){
            .server = {
                .bindaddr = m_toml.get_tbl()["crowapp"]["server"]["bindaddr"]
                                .value<std::string>()
                                .value(),
                .port = m_toml.get_tbl()["crowapp"]["server"]["port"]
                            .value<std::uint16_t>()
                            .value(),
                .threads = m_toml.get_tbl()["crowapp"]["server"]["threads"]
                               .value<std::uint16_t>()
                               .value(),
                .ssl_certificate_path =
                    m_toml
                        .get_tbl()["crowapp"]["server"]["ssl_certificate_path"]
                        .value<std::string>()
                        .value(),
                .context = {
                    .whitelist =
                        *m_toml
                             .get_tbl()["crowapp"]["server"]["websocket"]
                                       ["context"]["whitelist"]
                             .as_array()}}};
    }

    void Configuration::load_yara()
    {
        m_yara = (record::yara::Yara){
            .rules = {.malware_path =
                          m_toml.get_tbl()["yara"]["rules"]["malware_path"]
                              .value<std::string>()
                              .value(),
                      .packed_path =
                          m_toml.get_tbl()["yara"]["rules"]["packed_path"]
                              .value<std::string>()
                              .value(),
                      .cve_path = m_toml.get_tbl()["yara"]["rules"]["cve_path"]
                                      .value<std::string>()
                                      .value()}};
    }

    void Configuration::load_log()
    {
        m_log = (record::log::Log){
            .name = m_toml.get_tbl()["log"]["file"]["path"]
                        .value<std::string>()
                        .value(),
            .type =
                m_toml.get_tbl()["log"]["type"].value<std::string>().value(),
            .console = m_toml.get_tbl()["log"]["console"]["output_enabled"]
                           .value<bool>()
                           .value(),
            .level = m_toml.get_tbl()["log"]["level"].value<uint16_t>().value(),
            .trace = {.interval =
                          m_toml.get_tbl()["log"]["trace_updates"]["interval"]
                              .value<uint16_t>()
                              .value()},
            .daily_settings =
                {.hours = m_toml.get_tbl()["log"]["daily"]["hours"]
                              .value<uint16_t>()
                              .value(),
                 .minutes = m_toml.get_tbl()["log"]["daily"]["minutes"]
                                .value<uint16_t>()
                                .value(),
                 .max_size = m_toml.get_tbl()["log"]["daily"]["max_size"]
                                 .value<uint16_t>()
                                 .value()},
            .rotation_settings = {
                .max_files = m_toml.get_tbl()["log"]["rotation"]["max_files"]
                                 .value<uint16_t>()
                                 .value(),
                .max_size = m_toml.get_tbl()["log"]["rotation"]["max_size"]
                                .value<uint16_t>()
                                .value()}};
    }

} // namespace configuration