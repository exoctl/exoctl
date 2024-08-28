#include <engine/analysis/scan_yara.hxx>
#include <engine/security/yara/yara_exception.hxx>
#include <iostream>
#include <string>

namespace Analysis
{
ScanYara::~ScanYara() {}
ScanYara::ScanYara(Parser::Toml &p_config)
    : m_config(p_config),
      m_yara_rules(GET_TOML_TBL_VALUE(p_config, string, "yara", "rules"))
{
    dto_set_field("yara_rule", "none");
    dto_set_field("is_malicius", Security::Types::none);
}

const void
ScanYara::load_yara_rules(const std::function<void(void *)> &p_callback) const
{
    m_yara.yara_load_rules([&](void *p_rules_count)
                           { m_yara.yara_load_rules_folder(m_yara_rules); });

    p_callback((void *) m_yara.get_rules_loaded_count());
}

const void ScanYara::scan_yara_bytes(const std::string p_buffer)
{
    m_yara.yara_scan_bytes(
        p_buffer,
        [&](void *yr_user_data)
        {
            dto_set_field(
                "is_malicius",
                ((Security::yr_user_data *) yr_user_data)->is_malicius);

            if (((Security::yr_user_data *) yr_user_data)->is_malicius ==
                Security::Types::malicious)
            {
                dto_set_field(
                    "yara_rule",
                    ((Security::yr_user_data *) yr_user_data)->yara_rule);
            }
        });
}

} // namespace Analysis