#include <engine/plugins/plugins.hxx>
#include <engine/security/av/clamav/clamav.hxx>
#include <engine/security/av/clamav/extend/clamav.hxx>

namespace engine::security::av::clamav::extend
{
    void Clamav::bind_clamav()
    {
        plugins::Plugins::lua.state
            .new_usertype<engine::security::av::clamav::Clamav>(
                "Clamav",
                sol::constructors<engine::security::av::clamav::Clamav()>(),
                "set_db_rule_fd",
                &engine::security::av::clamav::Clamav::set_db_rule_fd,
                "scan_bytes",
                &engine::security::av::clamav::Clamav::scan_bytes,
                "load_rules",
                &engine::security::av::clamav::Clamav::load_rules,
                "rules_loaded_count",
                &engine::security::av::clamav::Clamav::rules_loaded_count);
    }

    void Clamav::bind_options()
    {
        plugins::Plugins::lua.state.new_usertype<clamav::record::scan::Options>(
            "ClamavOptions",
            "general",
            &clamav::record::scan::Options::general,
            "heuristic",
            &clamav::record::scan::Options::heuristic,
            "mail",
            &clamav::record::scan::Options::mail,
            "dev",
            &clamav::record::scan::Options::dev,
            "parse",
            &clamav::record::scan::Options::parse);
    }

    void Clamav::_plugins()
    {
        Clamav::bind_clamav();
        Clamav::bind_options();
    }
} // namespace engine::security::av::clamav::extend