#pragma once

#include <engine/exception.hxx>
#include <string>

namespace magic
{
    namespace exception
    {
        class Initialize : public ::exception::Exception
        {
          public:
            explicit Initialize(const std::string &);
        };

        class Finalize : public ::exception::Exception
        {
          public:
            explicit Finalize(const std::string &);
        };

    } // namespace exception
} // namespace magic
