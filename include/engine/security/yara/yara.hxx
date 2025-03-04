#pragma once

#include <engine/interfaces/iplugins.hxx>
#include <engine/security/yara/entitys.hxx>
#include <engine/security/yara/extend/yara.hxx>
#include <filesystem>
#include <functional>
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
             * @brief this function realize fast scan using flag
             * SCAN_FLAGS_FAST_MODE and if match rule return aborted callback
             * scan_fast_callback
             * @param string buffer for scan
             * @param callback receiver callback for pass parameter
             * Yr::Structs::Data scanned scan_fast_callback
             */
            void scan_fast_bytes(
                const std::string &,
                const std::function<void(yara::record::Data *)> &) const;

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
                            int) const;

            void rules_foreach(const std::function<void(const YR_RULE &)> &);

            void metas_foreach(YR_RULE *,
                               const std::function<void(const YR_META &)> &);

            void strings_foreach(
                YR_RULE *, const std::function<void(const YR_STRING &)> &);

            void tags_foreach(YR_RULE *,
                              const std::function<void(const char *)> &);

            void unload_stream_rules();
            [[nodiscard]] const int load_stream_rules(YR_STREAM &);
            [[nodiscard]] const int save_stream_rules(YR_STREAM &);
            [[nodiscard]] const int load_compiler();
            void unload_compiler();

            void load_rules(const std::function<void()> &) const;

            /* load rules if extension file '.yar'*/
            void load_rules_folder(const std::string & /* path */) const;

            [[nodiscard]] const int load_rule_buff(const std::string &,
                                                   const std::string &) const;
            [[nodiscard]] const int load_rule_file(const std::string &,
                                                   const std::string &,
                                                   const std::string &) const;

            mutable uint64_t rules_loaded_count;

          private:
            YR_COMPILER *m_yara_compiler;
            mutable YR_RULES *m_yara_rules;
            void compiler_rules() const;
            static YR_CALLBACK_FUNC scan_fast_callback(YR_SCAN_CONTEXT *,
                                                       const int,
                                                       void *,
                                                       void *);
        };
    } // namespace security
} // namespace engine