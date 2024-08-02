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
        const stypes scan_bytes(const uint8_t *, size_t) const override;

    private:
    };
}