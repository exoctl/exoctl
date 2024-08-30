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
    std::size_t m_pos;
};
} // namespace Security