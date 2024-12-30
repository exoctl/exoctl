#include <engine/parser/binary/lief/exception.hxx>

namespace engine::parser::binary::lief::exception
{
    Parser::Parser(const std::string &p_message) : m_error_message(p_message)
    {
    }

    const char *Parser::what() const noexcept
    {
        return m_error_message.c_str();
    }
} // namespace engine::parser::binary