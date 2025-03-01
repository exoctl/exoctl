#pragma once

namespace engine::security::yara
{
    namespace type
    {
        enum Scan {
            nomatch,
            match,
            none /* default value */
        };
    } // namespace type

    namespace record
    {
        using Data = struct Data {
            type::Scan match_status;
            const char *rule;
            const char *ns;
        };
    } // namespace record
} // namespace engine::security::yara
