#include "scan/yara/syara.hxx"
#include "scan/hash/shash.hxx"

#include <string>

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

        const void scan_bytes() const override;
        const void scan_yara(const std::string &);
        const void scan_hash(const std::string &);
        const void scan_file(const std::string) const override;
        const void load_rule(const std::string &, const std::function<void(void *)> &) const override;
    };
};