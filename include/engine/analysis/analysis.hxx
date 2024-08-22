#include <dto/analysis.hxx>
#include <engine/analysis/shash.hxx>
#include <engine/analysis/syara.hxx>
#include <engine/parser/toml.hxx>
#include <cstdint>
#include <string>

namespace Analysis
{
class Scan
{
  public:
    Scan();
    Scan(Parser::Toml &);
    ~Scan();

    const void scan_bytes(const std::string,
                          const std::function<void(void *)> &);
    const void load_rules(const std::function<void(void *)> &) const;

  private:
    const std::string m_yara_rules;
    Parser::Toml &m_config;
    SYara m_yara;
    SHash m_hash;
    DTOAnalysis m_analysis;
};
}; // namespace Analysis