#pragma once

#include <string>
#include <functional>
#include "uinterfaces.hxx"

namespace Analysis
{
    abstract_class IScan
    {
    public:
        IScan(){};
        virtual ~IScan(){};
        virtual const void scan_file(const std::string) const = 0;
        virtual const void load_rule(const std::function<void(void *)> &) const = 0;
    };
};