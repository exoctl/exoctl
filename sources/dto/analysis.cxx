#include "dto/analysis.hxx"

namespace Analysis
{
scan_t DTOAnalysis::dto_get_is_malicious() const { return m_is_malicious; }
const std::string &DTOAnalysis::dto_get_yara_rule() const { return m_yara_rule; }
bool DTOAnalysis::dto_get_is_packed() const { return m_is_packed; }
const std::string &DTOAnalysis::dto_get_packed() const { return m_packed; }

void DTOAnalysis::dto_set_is_malicious(scan_t p_is_malicious)
{
    m_is_malicious = p_is_malicious;
}
void DTOAnalysis::dto_set_yara_rule(const std::string &p_yara_rule)
{
    m_yara_rule = p_yara_rule;
}
void DTOAnalysis::dto_set_is_packed(bool p_is_packed)
{
    m_is_packed = p_is_packed;
}
void DTOAnalysis::dto_set_packed(const std::string &p_packed)
{
    m_packed = p_packed;
}

DTOAnalysis::DTOAnalysis() : m_is_malicious(scan_t::none), m_is_packed(false) {}

DTOAnalysis::DTOAnalysis(scan_t p_malicious,
                         std::string p_rule,
                         bool p_is_packed,
                         std::string p_packed)
    : m_is_malicious(p_malicious), m_yara_rule(std::move(p_rule)),
      m_is_packed(p_is_packed), m_packed(std::move(p_packed))

{
}

DTOAnalysis::~DTOAnalysis() {}

const std::string DTOAnalysis::dto_to_string_json()
{
    DTOAnalysis::dto_craft_json();
    return m_json.json_to_string();
}

inline void DTOAnalysis::dto_craft_json()
{
    m_json.json_craft({{"is_malicious", m_is_malicious},
                       {"yara_rule", m_yara_rule},
                       //{"is_packed", m_is_packed},
                       //{"packed", m_packed}
                       });
}
}; // namespace Analysis
