#pragma once

#include <engine/parser/elf.hxx>
#include <engine/security/signatures/lexer/lexer.hxx>
#include <engine/security/signatures/signatures_types.hxx>
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

struct Objs
{
    Parser::Elf o_elf;
};

class Sig
{
  public:
    Sig();
    ~Sig();

    Types::SigError_t sig_set_rule_mem(const std::string &,
                                       const std::string &);
    Types::SigError_t sig_set_rule_file(const std::string &,
                                        const std::string &);
    void sig_scan_file(const std::string &);
    void sig_scan_mem(const std::string &);

  private:
    LexerToken m_current_token;
    Lexer m_lexer;

    std::unordered_map<const std::string, SigRule> m_rules();

    void sig_parser_syntax(const std::string &);
    void sig_parser_imports(); 
    void sig_parser_sigrule();
    void sig_advance_token();
    bool sig_expect_token(Types::LexerToken);
};
} // namespace Security