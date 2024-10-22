#pragma once

#include <engine/interfaces/iexception.hxx>

namespace engine::memory::exception
{
    class Protection : public interface::IException
    {
      private:
        const std::string m_error_message;

      public:
        explicit Protection(const std::string &);
        const char *what() const noexcept override;
    };

    class Memfd : public interface::IException
    {
      private:
        const std::string m_error_message;

      public:
        explicit Memfd(const std::string &);
        const char *what() const noexcept override;
    };
} // namespace engine::memory::exception