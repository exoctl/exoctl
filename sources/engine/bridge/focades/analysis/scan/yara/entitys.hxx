#pragma once

#include <engine/security/yara/entitys.hxx>
#include <string>

namespace engine::bridge::focades::analysis::scan
{
    namespace yara
    {
        namespace record
        {
            typedef struct DTO {
                std::string rule;
                std::string ns;
                security::yara::type::Scan match_status;
            } DTO;
        } // namespace record
    } // namespace yara
} // namespace engine::bridge::focades::analysis::scan
