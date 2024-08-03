#pragma once

#include "iscan.hxx"
#include "string"

#include <yara.h>

namespace Analysis
{
    class SYara : public IScan
    {
    public:
        SYara();
        ~SYara();

        const stypes scan_bytes(const uint8_t *, size_t) const override;

        const void load_rules(const std::function<void(void *)> &) const override;
        const int syara_set_signature_rule_fd(const std::string &, const std::string &) const;
        const int syara_set_signature_rule_mem(const std::string &) const;
        const void syara_load_rules_folder(const std::string &) const;

    private:
        YR_COMPILER *m_yara_compiler;
        mutable YR_RULES *m_yara_rules;
        const void syara_compiler_rules() const;
    };
}