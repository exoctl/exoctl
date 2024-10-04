#pragma once

#include <engine/security/yara/entitys.hxx>
#include <string>

namespace focades
{
    namespace analysis
    {
        namespace scan
        {
            namespace yara
            {
                namespace record
                {
                    typedef struct DTO {
                        std::string yara_rule;
                        std::string yara_namespace;
                        security::yara::type::Scan yara_match_status;
                    } DTO;
                } // namespace record
            } // namespace yara
        } // namespace scan
    } // namespace analysis
} // namespace focades