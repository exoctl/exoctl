#pragma once

#include <engine/interfaces/iexception.hxx>
#include <string>

namespace magic
{
    namespace exception
    {
        class Initialize : public interface::IException
        {
          private:
            const std::string m_error_message;

          public:
            explicit Initialize(const std::string &);
            const char *what() const noexcept override;
        };

        class Finalize : public interface::IException
        {
          private:
            const std::string m_error_message;

          public:
            explicit Finalize(const std::string &);
            const char *what() const noexcept override;
        };

    } // namespace exception
} // namespace magic
