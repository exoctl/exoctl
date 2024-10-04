#pragma once

namespace security
{
    namespace yara
    {
        namespace type
        {
            enum Scan {
                yara_nomatch,
                yara_match,
                yara_none /* default value */
            };
        } // namespace Types

        namespace record
        {
            typedef struct Data {
                type::Scan yara_match_status;
                const char *yara_rule;
                const char *yara_namespace;
            } Data;
        } // namespace structs
    } // namespace Yr
} // namespace security