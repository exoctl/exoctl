#pragma once

#include <clamav.h>
#include <stdint.h>
#include <string>

namespace Security
{
    namespace Cl
    {
        namespace Types
        {
            enum Scan {
                clamav_clean,
                clamav_virus,
                clamav_none
            };
        } // namespace Types

        namespace Structs
        {
            typedef struct ScanOptions {
                uint32_t clamav_general;
                uint32_t clamav_parse;
                uint32_t clamav_heuristic;
                uint32_t clamav_mail;
                uint32_t clamav_dev;
            } Options;

            typedef struct Data {
                const char *clamav_virname;
                Types::Scan clamav_math_status;
            } Data;

        } // namespace Structs
    } // namespace Cl
} // namespace Security