#include "scan/yara/syara.hxx"
#include "scan/hash/shash.hxx"

#include <string>
#include <cstdint>

/*
    typescan:
            * yara
            * hash
*/
#define SCAN(Iobj, typescan, filepath) Iobj->scan_##typescan(filepath)

namespace Analysis
{
    class Scan : public IScan
    {
    public:
        Scan();
        ~Scan();

        const stypes scan_bytes(const uint8_t*, size_t) const override;
        const void scan_yara(const std::string &);
        const void scan_hash(const std::string &);
         const void load_rules( const std::function<void(void*)> &) const override;
    };
};