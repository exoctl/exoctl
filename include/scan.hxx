#include "scan/yara/syara.hxx"
#include "scan/hash/shash.hxx"

#include <string>
#include <cstdint>

namespace Analysis
{
    class Scan : public IScan
    {
    public:
        Scan();
        ~Scan();
        SYara m_yara;
        SHash m_hash;

        const stype  scan_bytes(const std::string, const std::function<void(void *)> &) const override;
        const void load_rules(const std::function<void(void *)> &) const override;
    };
};