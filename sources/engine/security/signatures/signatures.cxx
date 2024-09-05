#include <engine/security/signatures/signatures.hxx>
#include <engine/security/signatures/signatures_exception.hxx>
#include <fmt/core.h>

namespace Security
{

std::unordered_map<std::string_view, void *> Sig::m_objs;
std::unordered_map<std::string_view, SigRule> Sig::m_rules;
// std::unordered_map<SigRule, Include> Sig::m_includes;

Sig::Sig() { Sig::sig_init_objs_includes(); }
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
        if (Sig::sig_expect_token(Types::LexerToken::INCLUDE))
        {
            Sig::sig_parser_includes([](const char *p_include)
                                     { fmt::print("{}", p_include); });
        }
        else if (Sig::sig_expect_token(Types::LexerToken::SIG))
        {
            
        }
    }
}

/*
    p_rule:     @include("module1"); <other_code>
    Tokens:     [@include] [(] ["module1"] [)] [;] [other_code] [END]
    Processing:     |       |       |         |    |            |
                    |       |       |         |    |            |
    Advances:       1       2       3         4    ...          END
                    calls sig_parser_includes
  */
void Sig::sig_parser_includes(
    const std::function<void(const char *p_include)> &p_callback)
{
    if (!Sig::sig_expect_token(Types::LexerToken::INCLUDE))
    {
        throw SignaturesException::IncludeSig(
            "error: expected '@include' directive\n"
            "       @include(\"module\");\n"
            "       ^~~~~~~\n"
            "note: the @include directive is missing or incorrect");
    }

    Sig::sig_advance_token();

    if (!Sig::sig_expect_token(Types::LexerToken::LPAREN))
    {
        throw SignaturesException::IncludeSig(
            "error: expected '('\n"
            "       @include(\"module\");\n"
            "              ^\n"
            "note: the opening parenthesis '(' is missing or incorrect");
    }

    Sig::sig_advance_token();

    if (!Sig::sig_expect_token(Types::LexerToken::STRING))
    {
        throw SignaturesException::IncludeSig(
            "error: expected module name inside @include(\"module\")\n"
            "       @include(\"module\")\n"
            "               ^~~~~~~\n"
            "note: the module name is missing or incorrect");
    }

    if (!Sig::sig_includes_check(m_current_token.value))
    {
        throw SignaturesException::IncludeSig(
            "error: expected module name inside @include(\"module\")\n"
            "       @include(\"" +
            m_current_token.value +
            "\")\n"
            "                 ^~~~\n"
            "note: the module name is missing or incorrect");
    }
    const std::string include = std::move(m_current_token.value);

    Sig::sig_advance_token();

    if (!Sig::sig_expect_token(Types::LexerToken::RPAREN))
    {
        throw SignaturesException::IncludeSig(
            "error: expected ')'\n"
            "       @include(\"" +
            m_current_token.value +
            "\")\n"
            "                     ^\n"
            "note: the closing parenthesis ')' is missing or incorrect");
    }

    p_callback(include.c_str());
    Sig::sig_advance_token();
}
void Sig::sig_parser_sigrule() {}
bool Sig::sig_expect_token(Types::LexerToken p_token)
{
    if (p_token != m_current_token.type)
        return false;

    return true;
}

void Sig::sig_init_objs_includes()
{
    m_rules.emplace("test", nullptr);
    m_objs.emplace("elf", &m_elf);
}

bool Sig::sig_includes_check(const std::string &p_include)
{
    return m_objs.contains(p_include);
}
void Sig::sig_advance_token() { m_current_token = m_lexer.lexer_next_token(); }
} // namespace Security