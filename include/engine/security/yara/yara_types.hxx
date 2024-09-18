#pragma once

namespace Security
{
    namespace Types
    {
        enum Yara {
            yara_nomatch,
            yara_match,
            yara_none /* default value */
        };
    } // namespace Types
} // namespace Security