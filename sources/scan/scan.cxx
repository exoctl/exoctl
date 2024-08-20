#include "scan.hxx"
#include "string"

namespace Analysis
{
Scan::~Scan() {}
Scan::Scan(Parser::Toml &p_config)
    : m_config(p_config),
      m_yrules(GET_TOML_TBL_VALUE(p_config, string, "yara", "rules"))
{
}

const void Scan::load_rules(const std::function<void(void *)> &p_callback) const
{
    m_yara.syara_load_rules([&](void *)
                            { m_yara.syara_load_rules_folder(m_yrules); });

    p_callback(nullptr);
}

const void Scan::scan_bytes(const std::string p_buffer,
                            const std::function<void(void *)> &p_callback) const
{
    DTOAnalysis *analysis = new DTOAnalysis;

    m_yara.syara_scan_bytes(
        p_buffer,
        [&](void *yr_user_data)
        {
            analysis->is_malicious =
                ((Analysis::yr_user_data *) yr_user_data)->is_malicius;
            analysis->yrule = ((Analysis::yr_user_data *) yr_user_data)->yrule;
        });

    p_callback(analysis);

    delete analysis;
}
} // namespace Analysis