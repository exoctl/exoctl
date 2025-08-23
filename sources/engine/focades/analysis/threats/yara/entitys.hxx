#pragma once

#include <engine/security/yara/entitys.hxx>
#include <vector>

namespace engine::focades::analysis::threats
{
    namespace yara
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
            typedef struct DTO {
                std::vector<security::yara::type::Rule> rules;
                yara::type::Scan math_status;
            } DTO;
        } // namespace record
    } // namespace yara
} // namespace engine::focades::analysis::threats