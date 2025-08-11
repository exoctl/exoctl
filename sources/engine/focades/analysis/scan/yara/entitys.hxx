#pragma once

#include <engine/security/yara/entitys.hxx>
#include <vector>

namespace engine::focades::analysis::scan
{
    namespace yara
    {
        namespace record
        {
            typedef struct DTO {
                std::vector<security::yara::type::Rule> rules;
                security::yara::type::Scan math_status;
            } DTO;
        } // namespace record
    } // namespace yara
} // namespace engine::focades::analysis::scan