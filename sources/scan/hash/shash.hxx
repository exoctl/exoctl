#pragma once

#include "iscan.hxx"
#include "string"

namespace Analysis
{
    class SHash : public IScan
    {
    public:
        SHash();
        ~SHash();

        const void scan_file(const std::string ) const override;
        const void load_rule(const std::string &, const std::function<void(void *)> &) const override;
        const void scan_bytes() const override;

    private:
    };
}