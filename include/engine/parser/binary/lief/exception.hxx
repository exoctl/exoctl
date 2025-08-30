#pragma once

#include <engine/interfaces/iexception.hxx>

namespace engine::parser::binary::lief::exception
{
    class Parser : public interface::IException
    {
      private:
        const std::string error_message_;

      public:
        explicit Parser(const std::string &);
        const char *what() const noexcept override;
    };
} // namespace engine::parser::binary::lief::exception