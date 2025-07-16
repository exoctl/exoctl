#pragma once

#include <stdint.h>
#include <yara.h>

namespace engine::security::yara
{
    namespace type
    {
        enum Scan {
            nomatch,
            match,
            none /* default value */
        };
        using Rule = YR_RULE;
    } // namespace type
} // namespace engine::security::yara
