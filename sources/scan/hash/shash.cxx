#include "shash.hxx"

namespace Analysis
{
    SHash::SHash()
    {
    }

    SHash::~SHash()
    {
    }

    const void SHash::load_rules(const std::function<void(void*)> &p_callback) const
    {
    }

    const stypes SHash::scan_bytes(const uint8_t *p_bytes, size_t p_size) const 
    {
        return benign;
    }

};