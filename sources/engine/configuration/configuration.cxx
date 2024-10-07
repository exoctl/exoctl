#include <engine/configuration/configuration.hxx>

namespace configuration
{
    Configuration::Configuration(const std::string p_config)
        : m_path_config(p_config)
    {
        m_toml.parser_file(m_path_config);
    }

    void Configuration::load()
    {
        Configuration::load_clamav();
        Configuration::load_project();
        Configuration::load_crowapp();
        Configuration::load_yara();
        Configuration::load_sig();
        Configuration::load_cache();
        Configuration::load_log();
    }

    Configuration::~Configuration()
    {
    }

    const std::string &Configuration::get_path_config() const
    {
        return m_path_config;
    }

    const record::Cache &Configuration::get_cache() const
    {
        return m_cache;
    }

    const record::Clamav &Configuration::get_clamav() const
    {
        return m_clamav;
    }

    const record::Project &Configuration::get_project() const
    {
        return m_project;
    }

    const record::Yara &Configuration::get_yara() const
    {
        return m_yara;
    }

    const record::Log &Configuration::get_log() const
    {
        return m_log;
    }

    const record::Sig &Configuration::get_sig() const
    {
        return m_sig;
    }

    const record::CrowApp &Configuration::get_crowapp() const
    {
        return m_crowapp;
    }

    void Configuration::load_cache()
    {
        m_cache = (record::Cache){
            .type = GET_TOML_TBL_VALUE(m_toml, string, "cache", "type"),
            .name = GET_TOML_TBL_VALUE(m_toml, string, "cache", "name")};
    }

    void Configuration::load_clamav()
    {
        m_clamav =
            (record::Clamav){.default_database = GET_TOML_TBL_VALUE(
                                 m_toml, string, "clamav", "default_database")};
    }

    void Configuration::load_project()
    {
        m_project = (record::Project){
            .name = GET_TOML_TBL_VALUE(m_toml, string, "project", "name"),
            .version = GET_TOML_TBL_VALUE(m_toml, string, "project", "version"),
            .description =
                GET_TOML_TBL_VALUE(m_toml, string, "project", "description"),
            .copyright =
                GET_TOML_TBL_VALUE(m_toml, string, "project", "copyright")};
    }

    void Configuration::load_sig()
    {
        m_sig = (record::Sig){.packeds_rules = GET_TOML_TBL_VALUE(
                                  m_toml, string, "sig", "packeds_rules")};
    }

    void Configuration::load_crowapp()
    {
        m_crowapp = (record::CrowApp){
            .bindaddr =
                GET_TOML_TBL_VALUE(m_toml, string, "crowapp", "bindaddr"),
            .port = GET_TOML_TBL_VALUE(m_toml, uint16, "crowapp", "port"),
            .threads = GET_TOML_TBL_VALUE(m_toml, uint16, "crowapp", "threads"),
            .context_whitelist = GET_TOML_TBL_VALUE(
                m_toml, array, "crowapp", "context_whitelist")};
    }

    void Configuration::load_yara()
    {
        m_yara = (record::Yara){
            .malware_rules =
                GET_TOML_TBL_VALUE(m_toml, string, "yara", "malware_rules"),
            .packeds_rules =
                GET_TOML_TBL_VALUE(m_toml, string, "yara", "packeds_rules"),
            .cve_rules =
                GET_TOML_TBL_VALUE(m_toml, string, "yara", "cve_rules")};
    }

    void Configuration::load_log()
    {
        m_log = (record::Log){
            .name = GET_TOML_TBL_VALUE(m_toml, string, "log", "name"),
            .console = GET_TOML_TBL_VALUE(m_toml, bool, "log", "console"),
            .level = GET_TOML_TBL_VALUE(m_toml, uint16, "log", "level"),
            .trace = GET_TOML_TBL_VALUE(m_toml, uint16, "log", "trace"),
            .type = GET_TOML_TBL_VALUE(m_toml, string, "log", "type"),
            .max_files = GET_TOML_TBL_VALUE(m_toml, uint16, "log", "max_files"),
            .hours = GET_TOML_TBL_VALUE(m_toml, uint16, "log", "hours"),
            .minutes = GET_TOML_TBL_VALUE(m_toml, uint16, "log", "minutes"),
            .max_size = GET_TOML_TBL_VALUE(m_toml, uint16, "log", "max_size")};
    }

} // namespace configuration