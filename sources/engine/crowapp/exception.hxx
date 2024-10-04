#pragma once

#include <engine/exception.hxx>

namespace crowapp
{
    namespace exception
    {
        class Abort : public ::exception::Exception
        {
          public:
            explicit Abort(const std::string &);
        };
        class ParcialAbort : public ::exception::Exception
        {
          public:
            explicit ParcialAbort(const std::string &);
        };
    } // namespace exception
} // namespace crowapp