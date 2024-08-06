#include "scan.hxx"
#include "string"

namespace Analysis
{
    Scan::Scan() {}
    Scan::~Scan() {}

    const void Scan::load_rules(const std::function<void(void *)> &p_callback) const
    {
        m_yara.load_rules([&](void *)
                          { m_yara.syara_load_rules_folder("rules/yara"); });

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