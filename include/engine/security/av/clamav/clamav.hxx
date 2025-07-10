#pragma once

#include <clamav.h>
#include <engine/security/av/clamav/entitys.hxx>
#include <functional>
#include <mutex>
#include <string>

namespace engine
{
    namespace security
    {
        namespace av
        {
            class Clamav
            {
              private:
                struct cl_engine *m_engine;
                mutable std::mutex m_mutex;

              public:
                Clamav();
                ~Clamav();

                void set_db_rule_fd(const std::string &, unsigned int) const;
                void scan_bytes(
                    const std::string &,
                    clamav::record::scan::Options,
                    const std::function<void(clamav::record::Data *)> &);
                void load_rules(const std::function<void()> &);
                mutable unsigned int rules_loaded_count;
            };
        } // namespace av
    } // namespace security
} // namespace engine