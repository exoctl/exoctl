#include <engine/security/signatures/lexer/lexer.hxx>

namespace Security
{

Lexer::Lexer(const std::string &p_input) : m_input(p_input) {}
Lexer::~Lexer() {}

LexerToken Lexer::lexer_next_token()
{
    while (m_pos < m_input.size() && std::isspace(m_input[m_pos]))
        m_pos++;

    if (m_pos >= m_input.size())
        return (LexerToken){Types::LexerToken::END, ""};
}

} // namespace Security