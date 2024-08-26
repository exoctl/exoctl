#include <engine/dto.hxx>
#include <engine/parser/toml.hxx>
#include <engine/security/yara.hxx>

#include <cstdint>
#include <string>

namespace Analysis
{
class ScanYara : public DTOBase
{
  public:
    ScanYara();
    ScanYara(Parser::Toml &);
    ~ScanYara();

    const void scan_yara_bytes(const std::string);
    const void load_yara_rules(const std::function<void(void *)> &) const;

  private:
    const std::string m_yara_rules;
    Parser::Toml &m_config;
    Security::Yara m_yara;
};
}; // namespace Analysis