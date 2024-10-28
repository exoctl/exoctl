#pragma once

#include <engine/interfaces/iexception.hxx>

namespace engine::memory::exception
{
    class Protect : public interface::IException
    {
      private:
        const std::string m_error_message;

      public:
        explicit Protect(const std::string &);
        const char *what() const noexcept override;
    };

    class Fd : public interface::IException
    {
      private:
        const std::string m_error_message;

      public:
        explicit Fd(const std::string &);
        const char *what() const noexcept override;
    };

    class Write : public interface::IException
    {
      private:
        const std::string m_error_message;

      public:
        explicit Write(const std::string &);
        const char *what() const noexcept override;
    };
} // namespace engine::memory::exception