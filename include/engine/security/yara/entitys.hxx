#pragma once

namespace security
{
    namespace yara
    {
        namespace type
        {
            enum Scan {
                nomatch,
                match,
                none /* default value */
            };
        } // namespace Types

        namespace record
        {
            typedef struct Data {
                type::Scan match_status;
                const char *rule;
                const char *ns;
            } Data;
        } // namespace structs
    } // namespace Yr
} // namespace security