#pragma once

#include <engine/security/clamav/clamav_types.hxx>
#include <string>

namespace Focades
{
    namespace Analysis
    {
        namespace Scan
        {
            namespace Cl
            {
                namespace Structs
                {
                    typedef struct DTO {
                        const char *clamav_virname;
                        Security::Cl::Types::Scan clamav_math_status;
                    } DTO;
                } // namespace Structs
            } // namespace Cl
        } // namespace Scan
    } // namespace Analysis
} // namespace Focades