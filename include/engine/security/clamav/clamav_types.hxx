#pragma once

#include <string>
#include <clamav.h>

namespace Security
{
    namespace Cl
    {
        namespace Structs
        {
            typedef struct Data {
                const char *clamav_virname;
                cl_error_t clamav_math_status;
            } Data;
        } // namespace Structs
    } // namespace Clamav
} // namespace Security