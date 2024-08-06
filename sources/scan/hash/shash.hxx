#pragma once

#include "iscan.hxx"

#include <string>
#include <cstdint>
#include "stypes.hxx"

namespace Analysis
{
    class SHash : public IScan
    {
    public:
        SHash();
        ~SHash();

        const void load_rules(const std::function<void(void*)> &) const override;
        const stype  scan_bytes(const std::string, const std::function<void(void *)> &) const override;

    private:
    };
}