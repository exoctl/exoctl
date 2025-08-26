#pragma once

#include <clamav.h>
#include <engine/security/av/clamav/entitys.hxx>
#include <engine/security/av/clamav/extend/clamav.hxx>
#include <functional>
#include <mutex>
#include <string>

namespace engine::security::av::clamav
{
    class Clamav
    {
      private:
        struct cl_engine *engine_;
        mutable std::mutex mutex_;

      public:
        Clamav();
        ~Clamav();

        friend class extend::Clamav;

        void set_db_rule_fd(const std::string &, unsigned int) const;
        void scan_bytes(const std::string &,
                        clamav::record::scan::Options,
                        const std::function<void(clamav::record::Data *)> &);
        void load_rules();
        mutable unsigned int rules_loaded_count;
    };
} // namespace engine::security::av::clamav
