#pragma once

#include <engine/security/av/clamav/entitys.hxx>

namespace engine
{
    namespace focades
    {
        namespace analysis
        {
            namespace scan
            {
                namespace av
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
                } // namespace av
            } // namespace scan
        } // namespace analysis
    } // namespace focades
} // namespace engine