#pragma once

#include <clamav.h>
#include <engine/security/clamav/entitys.hxx>
#include <functional>
#include <string>

namespace security
{
    class Clamav
    {
      public:
        Clamav();
        ~Clamav();

        void clamav_set_db_rule_fd(const std::string &, unsigned int) const;
        const void clamav_scan_fast_bytes(
            const std::string &,
            clamav::record::scan::Options,
            const std::function<void(clamav::record::Data *)> &);
        void clamav_load_rules(const std::function<void()> &);
        [[nodiscard]] const unsigned int clamav_get_rules_loaded_count() const;

      private:
        struct cl_engine *m_engine;
        mutable unsigned int m_rules_loaded_count;
    };
} // namespace security