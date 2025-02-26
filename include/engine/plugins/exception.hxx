#ifdef ENGINE_PRO

#pragma once

#include <engine/interfaces/iexception.hxx>

namespace engine
{
    namespace plugins
    {
        namespace exception
        {
            class LoadPlugin : public interface::IException
            {
              private:
                const std::string m_error_message;

              public:
                explicit LoadPlugin(const std::string &);
                const char *what() const noexcept override;
            };

            class LoadLibraries : public interface::IException
            {
              private:
                const std::string m_error_message;

              public:
                explicit LoadLibraries(const std::string &);
                const char *what() const noexcept override;
            };
        } // namespace exception
    } // namespace plugins
} // namespace engine

#endif