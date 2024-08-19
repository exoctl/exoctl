#include "scan/yara/syara.hxx"
#include "scan/hash/shash.hxx"
#include "toml.hxx"
#include "analysis.hxx"

#include <string>
#include <cstdint>

namespace Analysis
{
    class Scan
    {
    public:
        Scan();
        Scan(Parser::Toml &);
        ~Scan();

        const void scan_bytes(const std::string, const std::function<void(void *)> &) const;
        const void load_rules(const std::function<void(void *)> &) const;

    private:
        const std::string m_yrules;
        Parser::Toml &m_config;
        SYara m_yara;
        SHash m_hash;
    };
};