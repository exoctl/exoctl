#pragma once

#include "iscan.hxx"
#include "string"

#include <yara.h>

namespace Analysis
{
    class SYara : public IScan
    {
    public:
        SYara();
        ~SYara();

        const void scan_file(const std::string) const override;
        const void load_rule(const std::string &, const std::function<void(void *)> &) const override;
        const void scan_bytes() const override;

    private:

        
    };
}