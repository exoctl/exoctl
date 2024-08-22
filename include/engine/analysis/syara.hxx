#pragma once

#include <dto/analysis.hxx>
#include <functional>
#include <stack>
#include <string>
#include <yara.h>

namespace Analysis
{
typedef struct yr_user_data
{
    scan_t is_malicius;
    const char *yara_rule;
} yr_user_data;

class SYara
{
  public:
    SYara();
    ~SYara();

    const void syara_scan_bytes(const std::string,
                                const std::function<void(void *)> &) const;
    const void syara_load_rules(const std::function<void(void *)> &) const;
    const void syara_load_rules_folder(const std::string &) const;
    const int syara_set_signature_rule_mem(const std::string &) const;
    const int syara_set_signature_rule_fd(const std::string &,
                                          const std::string &) const;

    const uint64_t get_rules_loaded_count() const;
  private:
    mutable uint64_t m_rules_loaded_count;
    YR_COMPILER *m_yara_compiler;
    mutable YR_RULES *m_yara_rules;
    const void syara_compiler_rules() const;
    static YR_CALLBACK_FUNC
    syara_scan_callback_default(YR_SCAN_CONTEXT *, const int, void *, void *);
};
} // namespace Analysis