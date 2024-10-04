#pragma once

#include <engine/exception.hxx>

namespace disassembly
{
    namespace capstone
    {
        namespace exception
        {
            class Initialize : public ::exception::Exception
            {
              public:
                explicit Initialize(const std::string &);
            };
        } // namespace exception
    } // namespace capstone
} // namespace disassembly