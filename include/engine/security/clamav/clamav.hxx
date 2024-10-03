#pragma once

#include <clamav.h>
#include <engine/security/clamav/clamav_types.hxx>
#include <functional>
#include <string>

namespace Security
{
    class Clamav
    {
      public:
        Clamav();
        ~Clamav();

        [[nodiscard]] const cl_error_t clamav_set_db_rule_fd(
            const std::string &, unsigned int) const;

        const void clamav_scan_bytes(
            const std::string &,
            const std::function<void(Cl::Structs::Data *)> &,
            cl_scan_options * = nullptr);
        void clamav_load_rules(const std::function<void()> &);

      private:
        struct cl_engine *m_engine;
        unsigned int *m_rules_loaded_count;
    };
} // namespace Security