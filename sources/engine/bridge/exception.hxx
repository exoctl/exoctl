#pragma once

#include <engine/exception.hxx>

namespace engine
{
    namespace bridge
    {
        namespace exception
        {
            class Abort : public interface::IException
            {
              private:
                const std::string m_error_message;

              public:
                explicit Abort(const std::string &);
                const char *what() const noexcept override;
            };

            class ParcialAbort : public interface::IException
            {
              private:
                const std::string m_error_message;

              public:
                explicit ParcialAbort(const std::string &);
                const char *what() const noexcept override;
            };
        } // namespace exception
    } // namespace server
} // namespace engine