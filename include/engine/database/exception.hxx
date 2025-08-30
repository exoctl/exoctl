#pragma once

#include <engine/interfaces/iexception.hxx>

namespace engine::database::exception
{
    class Initialize : public interface::IException
    {
      private:
        const std::string error_message_;

      public:
        explicit Initialize(const std::string &);
        const char *what() const noexcept override;
    };

    class Migrations : public interface::IException
    {
      private:
        const std::string error_message_;

      public:
        explicit Migrations(const std::string &);
        const char *what() const noexcept override;
    };

    class Schema : public interface::IException
    {
      private:
        const std::string error_message_;

      public:
        explicit Schema(const std::string &);
        const char *what() const noexcept override;
    };
} // namespace engine::database::exception