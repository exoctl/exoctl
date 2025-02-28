#pragma once

#include <engine/security/av/clamav/entitys.hxx>

namespace engine::bridge::focades::analysis::scan::av
{
    namespace clamav
    {
        namespace record
        {
            typedef struct DTO {
                const char *virname;
                security::av::clamav::type::Scan math_status;
            } DTO;
        } // namespace record
    } // namespace clamav
} // namespace engine::bridge::focades::analysis::scan::av