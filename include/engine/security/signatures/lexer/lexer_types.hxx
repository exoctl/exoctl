#pragma once

namespace Security
{
namespace Types
{
enum LexerToken
{
    IMPORT,
    IDENTIFIER,
    LBRACE, // {
    RBRACE, // }
    STRING,
    EQUALS, // =
    DOT,    // .
    END     // End of input
};
} // namespace Types
} // namespace Security