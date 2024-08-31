#pragma once

#include <engine/parser/elf.hxx>
#include <engine/security/signatures/signatues_types.hxx>
#include <unordered_map>

namespace Security
{

extern "C"
{
    struct SigRule
    {
        const char *sig_name;
        const char *sig_namespace;
    };
}

class Sig
{
  public:
    Sig();
    ~Sig();

    Types::SigError sig_set_rule_mem(const std::string &, const std::string &);
    Types::SigError sig_set_rule_file(const std::string &, const std::string &);
    void sig_scan_file(const std::string &);
    void sig_scan_mem(const std::string &);

  private:
    Parser::Elf m_elf;
    std::unordered_map<const std::string, SigRule> m_rules();

    void sig_parser_syntax(const std::string &);
    void sig_parser_import();
    void sig_parser_sigrule();
    void advance_token();
};
} // namespace Security