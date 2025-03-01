#pragma once

#include <clamav.h>
#include <cstdint>
#include <string>

namespace engine::security::av::clamav
{
    namespace type
    {
        enum Scan {
            clean,
            virus,
            none
        };
    } // namespace type

    namespace record
    {
        namespace scan
        {
            using Options = struct Options {
                uint32_t general;
                uint32_t parse;
                uint32_t heuristic;
                uint32_t mail;
                uint32_t dev;
            };
        } // namespace scan

        using Data = struct Data {
            const char *virname;
            type::Scan math_status;
        };
    } // namespace record
} // namespace engine::security::av::clamav
