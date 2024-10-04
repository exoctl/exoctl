#pragma once

#include <engine/exception.hxx>

namespace security
{
    namespace sig
    {
        namespace exception
        {
            class CompilerSig : public ::exception::Exception
            {
              public:
                explicit CompilerSig(const std::string &);
            };
        } // namespace exception
    } // namespace sig
} // namespace security