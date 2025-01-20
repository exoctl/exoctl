#pragma once

#include <engine/interfaces/iexception.hxx>

namespace engine::parser::binary::lief::exception
{
    class Parser : public interface::IException
    {
      private:
        const std::string m_error_message;

      public:
        explicit Parser(const std::string &);
        const char *what() const noexcept override;
    };
} // namespace engine::parser::binary::lief::exception