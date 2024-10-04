#pragma once

#include <engine/exception.hxx>

namespace engine
{
    namespace exception
    {
        class Run : public ::exception::Exception
        {
          public:
            explicit Run(const std::string &);
        };
    } // namespace exception
} // namespace engine