#include <engine/security/signatures/signatures.hxx>
#include <engine/security/signatures/signatures_exception.hxx>

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
    Sig::sig_parser_imports();
}
void Sig::sig_parser_imports()
{
    Sig::sig_advance_token(); // Skip '@include'
    if (!Sig::sig_expect_token(Types::LexerToken::LPAREN))
    {
        throw SignaturesException::ImportSig(
            "Expected token type: " +
            std::to_string(static_cast<int>(Types::LexerToken::LPAREN)) +
            ", but got: " + m_current_token.value);
    }
    Sig::sig_advance_token();

    if (m_current_token.type != Types::LexerToken::STRING)
    {
        throw SignaturesException::ImportSig(
            "Expected module name inside import(\"name\")");
    }

    Sig::sig_advance_token();
    Sig::sig_expect_token(Types::LexerToken::RPAREN);
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