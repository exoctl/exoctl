#pragma once

#include <engine/interfaces/iexception.hxx>

namespace engine
{
    namespace disassembly
    {
        namespace capstone
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
            } // namespace exception
        } // namespace capstone
    } // namespace disassembly
} // namespace engine