#include "shash.hxx"

namespace Analysis
{
    SHash::SHash()
    {
    }

    SHash::~SHash()
    {
    }

    const void SHash::load_rules(const std::function<void(void*)> & /*p_callback*/) const
    {
    }

    const stype  SHash::scan_bytes(const std::string p_buffer, const std::function<void(void *)> & /*p_callback*/ ) const 
    {
        
        return benign;
    }

};