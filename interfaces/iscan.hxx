#pragma once

#include <string>

namespace Scan
{
    class IScan
    {
    public:
        IScan(){};
        virtual ~IScan(){};
        virtual const void scan_file(const std::string &) const = 0;
    };
}