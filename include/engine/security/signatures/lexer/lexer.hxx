/*
    Generate tokens for small lang SIG
*/

#pragma once

#include <engine/security/signatures/lexer/lexer_types.hxx>
#include <string>

namespace Security
{

struct LexerToken
{
    Types::LexerToken type;
    const std::string value;
};

class Lexer
{
  public:
    Lexer(const std::string &);
    ~Lexer();

    LexerToken lexer_next_token();

  private:
    const std::string m_input;
    const std::size_t m_input_size;
    std::size_t m_pos;

    bool lexer_match_keyword(const std::string &);
    const LexerToken lexer_identifier_token();
    const LexerToken lexer_string_token();
};
} // namespace Security