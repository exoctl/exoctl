#pragma once

#include <string>
#include <functional>
#include <cstdint>

#include "uinterfaces.hxx"
#include "stypes.hxx"

namespace Analysis
{
    abstract_class IScan
    {
    public:
        IScan(){};
        virtual ~IScan(){};
        virtual const stypes scan_bytes(const uint8_t*, size_t) const = 0;
        virtual  const void load_rules( const std::function<void(void*)> &) const = 0;
    };
};