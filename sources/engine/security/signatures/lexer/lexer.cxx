#include <engine/security/signatures/lexer/lexer.hxx>
#include <engine/security/signatures/lexer/lexer_keywords.hxx>
#include <engine/security/signatures/signatures_exception.hxx>

namespace Security
{

Lexer::~Lexer() {}
Lexer::Lexer() : m_input(""), m_input_size(0), m_pos(0) {}

void Lexer::lexer_parser(const std::string &p_input)
{
    m_input.assign(p_input);
    m_input_size = p_input.size();
}
LexerToken Lexer::lexer_next_token()
{
    while (m_pos < m_input_size && std::isspace(m_input[m_pos]))
        m_pos++;

    if (m_pos >= m_input_size)
        return (LexerToken){Types::LexerToken::END, ""};

    if (Lexer::lexer_match_keyword(Keywords::include))
        return (LexerToken){Types::LexerToken::INCLUDE, Keywords::include};

    if (Lexer::lexer_match_keyword(Keywords::sig))
        return (LexerToken){Types::LexerToken::SIG, Keywords::sig};

    if (std::isalpha(m_input[m_pos]) || m_input[m_pos] == '_')
        return Lexer::lexer_identifier_token();

    switch (m_input[m_pos])
    {
    case ':':
        m_pos++;
        return (LexerToken){Types::LexerToken::COLON, ":"};
    case '{':
        m_pos++;
        return (LexerToken){Types::LexerToken::LBRACE, "{"};
    case '}':
        m_pos++;
        return (LexerToken){Types::LexerToken::RBRACE, "}"};
    case '(':
        m_pos++;
        return (LexerToken){Types::LexerToken::LPAREN, "("};
    case ')':
        m_pos++;
        return (LexerToken){Types::LexerToken::RPAREN, ")"};
    case '=':
        m_pos++;
        return (LexerToken){Types::LexerToken::EQUALS, "="};
    case '.':
        m_pos++;
        return (LexerToken){Types::LexerToken::DOT, "."};
    case '"':
        m_pos++;
        return Lexer::lexer_string_token();
    default:
        throw SignaturesException::LexerToken("Unexpected character: " +
                                              std::string(1, m_input[m_pos]));
    }
}

const LexerToken Lexer::lexer_identifier_token()
{
    std::string identifier;
    while (m_pos < m_input_size &&
           (std::isalnum(m_input[m_pos]) || m_input[m_pos] == '_'))
    {
        identifier += m_input[m_pos++];
    }
    return (LexerToken){Types::LexerToken::IDENTIFIER, identifier};
}

const LexerToken Lexer::lexer_string_token()
{
    std::string str;
    while (m_pos < m_input_size && m_input[m_pos] != '"')
    {
        str += m_input[m_pos++];
    }
    m_pos++; /* skip closing " */
    return (LexerToken){Types::LexerToken::STRING, str};
}

bool Lexer::lexer_match_keyword(const std::string &p_keyword)
{
    size_t start_pos = m_pos;
    for (char ch : p_keyword)
    {
        if (m_pos >= m_input_size || m_input[m_pos] != ch)
        {
            m_pos = start_pos;
            return false;
        }
        m_pos++;
    }

    if (m_pos < m_input_size &&
        (std::isalnum(m_input[m_pos]) || m_input[m_pos] == '_'))
    {
        m_pos = start_pos;
        return false;
    }

    return true;
}
} // namespace Security