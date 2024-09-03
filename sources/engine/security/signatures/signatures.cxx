#include <engine/security/signatures/signatures.hxx>
#include <engine/security/signatures/signatures_exception.hxx>
#include <iostream>

namespace Security
{
Sig::Sig() {}
Sig::~Sig() {}

Types::SigError_t Sig::sig_set_rule_mem(const std::string &p_rule,
                                        const std::string &p_namespace)
{
    Sig::sig_parser_syntax(p_rule);

    return Types::SigError_t::sig_success;
}
Types::SigError_t Sig::sig_set_rule_file(const std::string &p_rule,
                                         const std::string &p_namespace)
{
    return Types::SigError_t::sig_success;
}

void Sig::sig_parser_syntax(const std::string &p_rule)
{
    m_lexer.lexer_parser(p_rule);
    while (!Sig::sig_expect_token(Types::LexerToken::END))
    {
        Sig::sig_advance_token();
        if (Sig::sig_expect_token(Types::LexerToken::IMPORT))
            Sig::sig_parser_imports();
    }
}

/*
    p_rule:     @import("module1"); <other_code>
    Tokens:     [@import] [(] ["module1"] [)] [;] [other_code] [END]
    Processing:     |       |       |         |    |            |
                    |       |       |         |    |            |
    Advances:       1       2       3         4    ...          END
                    calls sig_parser_imports
  */
void Sig::sig_parser_imports()
{
    if (!Sig::sig_expect_token(Types::LexerToken::IMPORT))
    {
        throw SignaturesException::ImportSig(
            "error: expected '@import' directive\n"
            "       @import(\"module\");\n"
            "       ^~~~~~~\n"
            "note: the @import directive is missing or incorrect");
    }

    Sig::sig_advance_token();

    if (!Sig::sig_expect_token(Types::LexerToken::LPAREN))
    {
        throw SignaturesException::ImportSig(
            "error: expected '('\n"
            "       @import(\"module\");\n"
            "              ^\n"
            "note: the opening parenthesis '(' is missing or incorrect");
    }

    Sig::sig_advance_token();

    if (m_current_token.type != Types::LexerToken::STRING)
    {
        throw SignaturesException::ImportSig(
            "error: expected module name inside @import(\"module\")\n"
            "       @import(\"module\");\n"
            "               ^~~~~~~\n"
            "note: the module name is missing or incorrect");
    }

    Sig::sig_advance_token();

    if (!Sig::sig_expect_token(Types::LexerToken::RPAREN))
    {
        throw SignaturesException::ImportSig(
            "error: expected ')'\n"
            "       @import(\"module\");\n"
            "                       ^\n"
            "note: the closing parenthesis ')' is missing or incorrect");
    }

    Sig::sig_advance_token();
}
void Sig::sig_parser_sigrule() {}
bool Sig::sig_expect_token(Types::LexerToken p_token)
{
    if (p_token != m_current_token.type)
        return false;

    return true;
}
void Sig::sig_advance_token() { m_current_token = m_lexer.lexer_next_token(); }
} // namespace Security