#pragma once

#include <engine/security/clamav/entitys.hxx>
#include <string>

namespace focades
{
    namespace analysis
    {
        namespace scan
        {
            namespace clamav
            {
                namespace record
                {
                    typedef struct DTO {
                        const char *virname;
                        security::clamav::type::Scan math_status;
                    } DTO;
                } // namespace record
            } // namespace clamav
        } // namespace scan
    } // namespace analysis
} // namespace focades