#pragma once

namespace Security
{
namespace Types
{
enum LexerToken
{
    INCLUDE, // Keywords::import
    IDENTIFIER,
    LBRACE, // {
    RBRACE, // }
    LPAREN, // (
    RPAREN, // ) 
    STRING,
    EQUALS, // =
    DOT,    // .
    END     // End of input
};
} // namespace Types
} // namespace Security