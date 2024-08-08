#pragma once

#include "iscan.hxx"
#include "string"

#include <yara.h>
#include <stack>

namespace Analysis
{
    typedef struct yr_user_data
    {
        stype is_malicius = benign;
        const char* rule;
    } yr_user_data;

    class SYara : public IScan
    {
    public:
        SYara();
        ~SYara();

        const stype scan_bytes(const std::string, const std::function<void(void *)> &) const override;
        const void load_rules(const std::function<void(void *)> &) const override;
        const void syara_load_rules_folder(const std::string &) const;
        const int syara_set_signature_rule_mem(const std::string &) const;
        const int syara_set_signature_rule_fd(const std::string &, const std::string &) const;

    private:
        YR_COMPILER *m_yara_compiler;
        mutable YR_RULES *m_yara_rules;
        const void syara_compiler_rules() const;
        static YR_CALLBACK_FUNC syara_scan_callback_default(YR_SCAN_CONTEXT *,
                                                      const int,
                                                      void *,
                                                      void *);
    };
}