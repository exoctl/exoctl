#pragma once

#include <engine/exception.hxx>

namespace Security
{
    namespace ClamavException
    {
        class Initialize : public Exception::ExceptionBase
        {
          public:
            explicit Initialize(const std::string &);
        };

        class LoadRules : public Exception::ExceptionBase
        {
          public:
            explicit LoadRules(const std::string &);
        };

        class SetDbRules : public Exception::ExceptionBase
        {
          public:
            explicit SetDbRules(const std::string &);
        };
    } // namespace ClamavException
} // namespace Security