#pragma once

#include <functional>
#include <stack>
#include <string>
#include <yara.h>
#include <engine/security/yara_types.hxx>

namespace Security
{
typedef struct yr_user_data
{
    YaraTypes::scan_t is_malicius;
    const char *yara_rule;
} yr_user_data;

class Yara
{
  public:
    Yara();
    ~Yara();

    const void yara_scan_bytes(const std::string,
                                const std::function<void(void *)> &) const;
    const void yara_load_rules(const std::function<void(void *)> &) const;
    const void yara_load_rules_folder(const std::string &) const;
    const int yara_set_signature_rule_mem(const std::string &) const;
    const int yara_set_signature_rule_fd(const std::string &,
                                          const std::string &) const;

    const uint64_t get_rules_loaded_count() const;
  private:
    mutable uint64_t m_rules_loaded_count;
    YR_COMPILER *m_yara_compiler;
    mutable YR_RULES *m_yara_rules;
    const void yara_compiler_rules() const;
    static YR_CALLBACK_FUNC
    yara_scan_callback_default(YR_SCAN_CONTEXT *, const int, void *, void *);
};
} // namespace Security