#pragma once

#include <engine/exception.hxx>

namespace Security
{
    namespace SignaturesException
    {
        class CompilerSig : public Exception::ExceptionBase
        {
          public:
            explicit CompilerSig(const std::string &);
        };
    } // namespace SignaturesException
} // namespace Security