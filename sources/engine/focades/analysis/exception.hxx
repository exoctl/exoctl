#pragma once

#include <engine/interfaces/iexception.hxx>

namespace engine::focades::analysis::exception
{
    class Scan : public interface::IException
    {
      private:
        const std::string error_message_;

      public:
        explicit Scan(const std::string &);
        const char *what() const noexcept override;
    };

    class Load : public interface::IException
    {
      private:
        const std::string error_message_;

      public:
        explicit Load(const std::string &);
        const char *what() const noexcept override;
    };
} // namespace engine::focades::analysis::exception