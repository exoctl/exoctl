#pragma once

#include <engine/interfaces/iexception.hxx>

namespace engine::database::exception
{
    class Initialize : public interface::IException
    {
      private:
        const std::string m_error_message;

      public:
        explicit Initialize(const std::string &);
        const char *what() const noexcept override;
    };

    class Migrations : public interface::IException
    {
      private:
        const std::string m_error_message;

      public:
        explicit Migrations(const std::string &);
        const char *what() const noexcept override;
    };
} // namespace engine::database::exception