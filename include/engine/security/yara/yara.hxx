#pragma once

#include <engine/security/yara/yara_types.hxx>
#include <filesystem>
#include <functional>
#include <stack>
#include <string>
#include <yara.h>

namespace Security
{
    class Yara
    {
      public:
        Yara();
        ~Yara();

        /**
         * @brief this function realize fast scan using flag
         * SCAN_FLAGS_FAST_MODE and if match rule return aborted callback
         * yara_scan_fast_callback
         * @param string buffer for scan
         * @param callback receiver callback for pass parameter Structs::Data
         * scanned yara_scan_fast_callback
         */
        void yara_scan_fast_bytes(
            const std::string,
            const std::function<void(Structs::Data *)> &) const;

        /**
         * @brief function for scan, but, you pass flag and callback for scan
         * yara YR_CALLBACK_FUNC
         * @param YR_CALLBACK_FUNC callback for scan yara
         * @param void* user_data, pass for example Structs::Data*
         * @param int flags used for scan
         */
        void yara_scan_bytes(const std::string,
                             YR_CALLBACK_FUNC,
                             void *,
                             int) const;
        void yara_load_rules(const std::function<void(void *)> &) const;

        /* load rules if extension file '.yar'*/
        void yara_load_rules_folder(
            const std::filesystem::path & /* path */) const;

        const int yara_set_signature_rule_mem(const std::string &,
                                              const std::string &) const;
        const int yara_set_signature_rule_fd(const std::string &,
                                             const std::string &,
                                             const std::string &) const;

        const uint64_t get_rules_loaded_count() const;

      private:
        YR_COMPILER *m_yara_compiler;
        mutable YR_RULES *m_yara_rules;
        mutable uint64_t m_rules_loaded_count;
        void yara_compiler_rules() const;
        static YR_CALLBACK_FUNC yara_scan_fast_callback(YR_SCAN_CONTEXT *,
                                                        const int,
                                                        void *,
                                                        void *);
    };
} // namespace Security