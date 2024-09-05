#pragma once

namespace Security
{
namespace Types
{
enum LexerToken
{
    SIG,     // Keywords::sig
    INCLUDE, // Keywords::import
    IDENTIFIER,
    LBRACE, // {
    RBRACE, // }
    LPAREN, // (
    RPAREN, // )
    STRING,
    EQUALS, // =
    DOT,    // .
    COLON,
    END // End of input
};
} // namespace Types
} // namespace Security