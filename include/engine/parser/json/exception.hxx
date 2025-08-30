#pragma once

#include <engine/interfaces/iexception.hxx>

namespace engine::parser::json::exception
{
    class Add : public interface::IException
    {
      private:
        const std::string error_message_;

      public:
        explicit Add(const std::string &);
        const char *what() const noexcept override;
    };
} // namespace engine::parser::json::exception