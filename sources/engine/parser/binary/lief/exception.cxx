#include <engine/parser/binary/lief/exception.hxx>

namespace engine::parser::binary::lief::exception
{
    Parser::Parser(const std::string &p_message) : error_message_(p_message)
    {
    }

    const char *Parser::what() const noexcept
    {
        return error_message_.c_str();
    }
} // namespace engine::parser::binary::lief::exception