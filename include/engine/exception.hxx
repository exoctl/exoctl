#pragma once

#include <engine/interfaces/iexception.hxx>

namespace engine
{
    namespace exception
    {
        class Run : public interface::IException
        {
          private:
            const std::string m_error_message;

          public:
            explicit Run(const std::string &);
            const char *what() const noexcept override;
        };
    } // namespace exception
} // namespace engine