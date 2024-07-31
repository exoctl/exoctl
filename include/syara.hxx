#pragma once

#include "iscan.hxx"
#include "string"

namespace Scan
{
    class SYara : public IScan
    {
    public:
        SYara();
        ~SYara();

        const void scan_file(const std::string &) const override;

    private:
    };
}