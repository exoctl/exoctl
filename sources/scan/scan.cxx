#include "scan.hxx"
#include "string"

namespace Analysis
{
    Scan::Scan() : m_yrules("rules/yara"), m_config(m_config) {}
    Scan::~Scan() {}
    Scan::Scan(Parser::Toml &p_config) : m_config(p_config),
                                         m_yrules(GET_TOML_TBL_VALUE(p_config, string, "yara", "rules"))
    {}

    const void Scan::load_rules(const std::function<void(void *)> &p_callback) const
    {
        m_yara.load_rules([&](void *)
                          {  m_yara.syara_load_rules_folder(m_yrules); });

        m_hash.load_rules([&](void *) {

        });

        p_callback(nullptr);
    }

    const stype Scan::scan_bytes(const std::string p_buffer, const std::function<void(void *)> &p_callback) const
    {
        const stype is_malicius = [&]() -> const stype
        {
            return (m_hash.scan_bytes(p_buffer, p_callback) == benign) ? m_yara.scan_bytes(p_buffer, p_callback) : malicious;
        }();

        return is_malicius;
    }
}