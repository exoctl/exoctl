#pragma once

#include <engine/exception.hxx>
#include <string>

namespace Security
{
    namespace YaraException
    {
        class CompilerRules : public Exception::ExceptionBase
        {
          public:
            explicit CompilerRules(const std::string &);
        };

        class LoadRules : public Exception::ExceptionBase
        {
          public:
            explicit LoadRules(const std::string &);
        };

        class Initialize : public Exception::ExceptionBase
        {
          public:
            explicit Initialize(const std::string &);
        };

        class Finalize : public Exception::ExceptionBase
        {
          public:
            explicit Finalize(const std::string &);
        };

        class Scan : public Exception::ExceptionBase
        {
          public:
            explicit Scan(const std::string &);
        };

    } // namespace YaraException
} // namespace Security
