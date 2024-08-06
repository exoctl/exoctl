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
        virtual const stype  scan_bytes(const std::string, const std::function<void(void *)> &) const = 0;
        virtual  const void load_rules( const std::function<void(void*)> &) const = 0;
    };
};