#pragma once

namespace Security
{
    namespace Types
    {
        enum Scan {
            yara_nomatch,
            yara_match,
            yara_none /* default value */
        };
    } // namespace Types

    namespace Structs
    {
        typedef struct Data {
            Types::Scan yara_match_status;
            const char *yara_rule;
            const char *yara_namespace;
        } Data;
    } // namespace Structs

} // namespace Security