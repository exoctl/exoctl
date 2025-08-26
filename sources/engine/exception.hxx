#pragma once

#include <engine/interfaces/iexception.hxx>

namespace engine
{
    namespace exception
    {
        class Run : public interface::IException
        {
          private:
            const std::string error_message_;

          public:
            explicit Run(const std::string &);
            const char *what() const noexcept override;
        };
    } // namespace exception
} // namespace engine