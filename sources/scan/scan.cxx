#include "scan.hxx"
#include "string"

namespace Analysis
{
Scan::~Scan() {}
Scan::Scan(Parser::Toml &p_config)
    : m_config(p_config),
      m_yara_rules(GET_TOML_TBL_VALUE(p_config, string, "yara", "rules")),
      m_analysis()
{
}

const void Scan::load_rules(const std::function<void(void *)> &p_callback) const
{
    m_yara.syara_load_rules([&](void *)
                            { m_yara.syara_load_rules_folder(m_yara_rules); });

    p_callback(nullptr);
}

const void Scan::scan_bytes(const std::string p_buffer,
                            const std::function<void(void *)> &p_callback) const
{
    m_yara.syara_scan_bytes(
        p_buffer,
        [&](void *yr_user_data)
        {
            m_analysis.dto_set_is_malicious(
                ((Analysis::yr_user_data *) yr_user_data)->is_malicius);

            if (((Analysis::yr_user_data *) yr_user_data)->yara_rule != nullptr)
            {
                m_analysis.dto_set_yara_rule(
                    ((Analysis::yr_user_data *) yr_user_data)->yara_rule);
            }
        });

    p_callback(&m_analysis);
}
} // namespace Analysis