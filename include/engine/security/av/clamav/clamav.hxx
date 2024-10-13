#pragma once

#include <clamav.h>
#include <engine/security/av/clamav/entitys.hxx>
#include <functional>
#include <string>

namespace engine
{
    namespace security
    {
        namespace av
        {
            class Clamav
            {
              public:
                Clamav();
                ~Clamav();

                void set_db_rule_fd(const std::string &, unsigned int) const;
                const void scan_fast_bytes(
                    const std::string &,
                    clamav::record::scan::Options,
                    const std::function<void(clamav::record::Data *)> &);
                void load_rules(const std::function<void()> &);
                [[nodiscard]] const unsigned int get_rules_loaded_count() const;

              private:
                struct cl_engine *m_engine;
                mutable unsigned int m_rules_loaded_count;
            };
        } // namespace av
    } // namespace security
} // namespace engine