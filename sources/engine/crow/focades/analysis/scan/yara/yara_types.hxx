#pragma once

#include <engine/security/yara/yara_types.hxx>
#include <string>

namespace Focades
{
    namespace Analysis
    {
        namespace Scan
        {
            namespace Structs
            {
                typedef struct DTO {
                    std::string yara_rule;
                    std::string yara_namespace;
                    Security::Types::Scan yara_match_status;
                } DTO;
            } // namespace Structs
        } // namespace Scan
    } // namespace Analysis
} // namespace Focades