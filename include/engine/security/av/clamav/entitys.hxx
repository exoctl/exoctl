#pragma once

#include <clamav.h>
#include <stdint.h>
#include <string>

namespace security
{
    namespace av
    {
        namespace clamav
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
                    typedef struct Options {
                        uint32_t general;
                        uint32_t parse;
                        uint32_t heuristic;
                        uint32_t mail;
                        uint32_t dev;
                    } Options;
                } // namespace scan

                typedef struct Data {
                    const char *virname;
                    type::Scan math_status;
                } Data;
            } // namespace record
        } // namespace clamav
    } // namespace av
} // namespace security