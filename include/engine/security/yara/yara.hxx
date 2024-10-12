#pragma once

#include <engine/security/yara/entitys.hxx>
#include <filesystem>
#include <functional>
#include <stack>
#include <string>
#include <yara.h>

namespace security
{
    class Yara
    {
      public:
        Yara();
        ~Yara();

        /**
         * @brief this function realize fast scan using flag
         * SCAN_FLAGS_FAST_MODE and if match rule return aborted callback
         * scan_fast_callback
         * @param string buffer for scan
         * @param callback receiver callback for pass parameter
         * Yr::Structs::Data scanned scan_fast_callback
         */
        void scan_fast_bytes(
            const std::string,
            const std::function<void(yara::record::Data *)> &) const;

        /**
         * @brief function for scan, but, you pass flag and callback for scan
         * yara YR_CALLBACK_FUNC
         * @param YR_CALLBACK_FUNC callback for scan yara
         * @param void* user_data, pass for example Yr::Structs::Data
         * @param int flags used for scan
         */
        void scan_bytes(const std::string, YR_CALLBACK_FUNC, void *, int) const;
        void load_rules(const std::function<void()> &) const;

        /* load rules if extension file '.yar'*/
        void load_rules_folder(const std::filesystem::path & /* path */) const;

        [[nodiscard]] const int set_signature_rule_mem(
            const std::string &, const std::string &) const;
        [[nodiscard]] const int yara_set_signature_rule_fd(
            const std::string &,
            const std::string &,
            const std::string &) const;

        [[nodiscard]] const uint64_t get_rules_loaded_count() const;

      private:
        YR_COMPILER *m_yara_compiler;
        mutable YR_RULES *m_yara_rules;
        mutable uint64_t m_rules_loaded_count;
        void compiler_rules() const;
        static YR_CALLBACK_FUNC scan_fast_callback(YR_SCAN_CONTEXT *,
                                                   const int,
                                                   void *,
                                                   void *);
    };
} // namespace security