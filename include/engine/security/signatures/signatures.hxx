#pragma once

#include <engine/parser/elf.hxx>
#include <engine/security/signatures/signatues_types.hxx>
#include <vector>

namespace Security
{

extern "C"
{
    struct SigRule
    {
        const char *sig_name;
    };
}

class Sig
{
  public:
    Sig();
    ~Sig();

    Types::SigError sig_set_rule_mem(const std::string &);
    Types::SigError sig_set_rule_file(const std::string &);

  private:
    Parser::Elf m_elf;
    std::vector<SigRule> m_rules;

    void sig_identify_import();
};
} // namespace Security