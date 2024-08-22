#pragma once

#include <engine/parser/json.hxx>

namespace Analysis
{
enum scan_t
{
    benign,
    malicious,
    none
};

class DTOAnalysis
{
  private:
    Parser::Json m_json;
    scan_t m_is_malicious;
    std::string m_yara_rule;
    bool m_is_packed;
    std::string m_packed;

    void  dto_craft_json();

  public:
    scan_t dto_get_is_malicious() const;
    const std::string &dto_get_yara_rule() const;
    bool dto_get_is_packed() const;
    const std::string &dto_get_packed() const;

    void dto_set_is_malicious(scan_t value);
    void dto_set_yara_rule(const std::string &value);
    void dto_set_is_packed(bool value);
    void dto_set_packed(const std::string &value);

    DTOAnalysis();
    DTOAnalysis(scan_t, std::string, bool, std::string);
    ~DTOAnalysis();

    const std::string dto_to_string_json();
};
} // namespace Analysis