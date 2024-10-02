#pragma once

#include <engine/exception.hxx>

namespace Disassembly
{
    namespace CapstoneException
    {

        class Initialize : public Exception::ExceptionBase
        {
          public:
            explicit Initialize(const std::string &);
        };
    } // namespace CapstoneException
} // namespace Disassembly