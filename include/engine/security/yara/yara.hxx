#pragma once

#include <engine/security/yara/yara_types.hxx>
#include <filesystem>
#include <functional>
#include <stack>
#include <string>
#include <yara.h>

namespace Security
{
    typedef struct yr_user_data {
        Types::Yara yara_is_match;
        const char *yara_rule;
        const char *yara_namespace;
    } yr_user_data;

    class Yara
    {
      public:
        Yara();
        ~Yara();

        void yara_scan_bytes(const std::string,
                             const std::function<void(void *)> &) const;
        void yara_load_rules(const std::function<void(void *)> &) const;

        /* load rules if extension file '.yar'*/
        void yara_load_rules_folder(
            const std::filesystem::path & /* path */) const;

        const int yara_set_signature_rule_mem(const std::string &) const;
        const int yara_set_signature_rule_fd(const std::string &,
                                             const std::string &,
                                             const std::string &) const;

        const uint64_t get_rules_loaded_count() const;

      private:
        YR_COMPILER *m_yara_compiler;
        mutable YR_RULES *m_yara_rules;
        mutable uint64_t m_rules_loaded_count;
        void yara_compiler_rules() const;
        static YR_CALLBACK_FUNC yara_scan_callback_default(YR_SCAN_CONTEXT *,
                                                           const int,
                                                           void *,
                                                           void *);
    };
} // namespace Security