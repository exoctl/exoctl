#pragma once

#include <clamav.h>
#include <stdint.h>
#include <string>

namespace security
{
    namespace clamav
    {
        namespace type
        {
            enum Scan {
                clamav_clean,
                clamav_virus,
                clamav_none
            };
        } // namespace type

        namespace record
        {
            namespace scan
            {
                typedef struct Options {
                    uint32_t clamav_general;
                    uint32_t clamav_parse;
                    uint32_t clamav_heuristic;
                    uint32_t clamav_mail;
                    uint32_t clamav_dev;
                } Options;
            } // namespace scan

            typedef struct Data {
                const char *clamav_virname;
                type::Scan clamav_math_status;
            } Data;

        } // namespace record
    } // namespace clamav
} // namespace security