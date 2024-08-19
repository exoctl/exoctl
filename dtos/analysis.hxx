#pragma once

namespace Analysis
{
    enum scan_t
    {
        benign,
        malicious,
        none
    };

    struct DTOAnalysis
    {
        scan_t is_malicious : 2;
        const char *yrule;
        bool is_packed;
        const char *packed;
    };
}