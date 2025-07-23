#pragma once

#include <atomic>
#include <engine/interfaces/iplugins.hxx>
#include <engine/security/yara/entitys.hxx>
#include <engine/security/yara/extend/yara.hxx>
#include <filesystem>
#include <functional>
#include <shared_mutex>
#include <stack>
#include <string>
#include <yara.h>

namespace engine
{
    namespace security
    {
        class Yara; // Forward declaration yara plugin

        class Yara
        {
          public:
            Yara();
            ~Yara();

            friend class yara::extend::Yara;

            /**
             * @brief function for scan, but, you pass flag and callback for
             * scan yara YR_CALLBACK_FUNC
             * @param YR_CALLBACK_FUNC callback for scan yara
             * @param void* user_data, pass for example Yr::Structs::Data
             * @param int flags used for scan
             */
            void scan_bytes(const std::string &,
                            YR_CALLBACK_FUNC,
                            void *,
                            yara::type::Flags) const;

            void rule_disable(YR_RULE &);
            void rule_enable(YR_RULE &);
            void rules_foreach(const std::function<void(const YR_RULE &)> &);

            void metas_foreach(YR_RULE *,
                               const std::function<void(const YR_META &)> &);

            void strings_foreach(
                YR_RULE *, const std::function<void(const YR_STRING &)> &);

            void tags_foreach(YR_RULE *,
                              const std::function<void(const char *)> &);

            const int load_rules_file(const char *);
            const int save_rules_file(const char *);

            void unload_rules();
            [[nodiscard]] const int load_rules_stream(YR_STREAM &);
            [[nodiscard]] const int save_rules_stream(YR_STREAM &);
            [[nodiscard]] const int load_compiler();
            void unload_compiler();

            void load_rules() const;

            /* load rules if extension file '.yar'*/
            void set_rules_folder(const std::string & /* path */) const;

            [[nodiscard]] const int set_rule_buff(const std::string &,
                                                  const std::string &) const;
            [[nodiscard]] const int set_rule_file(const std::string &,
                                                  const std::string &,
                                                  const std::string &) const;

          private:
            mutable std::mutex m_compiler_mutex;
            mutable std::shared_mutex m_rules_mutex;

            template <typename Callback>
            void execute_safely(Callback &&cb) const
            {
                const std::shared_lock<std::shared_mutex> lock(m_rules_mutex);
                cb();
            }

            YR_COMPILER *m_yara_compiler;
            mutable YR_RULES *m_yara_rules;
            void compiler_rules() const;
        };
    } // namespace security
} // namespace engine