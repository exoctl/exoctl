#include "scan.hxx"
#include "string"

namespace Analysis
{
    Scan::Scan() {}
    Scan::~Scan() {}

    const void Scan::scan_yara(const std::string &p_filepath)
    {
    }

    const void Scan::scan_hash(const std::string &p_filepath)
    {
    }

    const void Scan::load_rules(const std::function<void(void*)> &p_callback) const
    {
    }

    const stypes Scan::scan_bytes(const uint8_t*, size_t) const
    {
        IScan *m_scan = new SYara();

        m_scan = new SHash();

        delete m_scan;
    }
}