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

    /*
        All scan checking file is malicius
    */
    const void Scan::scan_file(const std::string p_filepath) const
    {
        IScan *m_scan = new SYara();
        m_scan->scan_file(p_filepath);

        m_scan = new SHash();
        m_scan->scan_file(p_filepath);

        delete m_scan;
    }

    const void Scan::load_rule(const std::function<void(void *)> &) const
    {
    }
}