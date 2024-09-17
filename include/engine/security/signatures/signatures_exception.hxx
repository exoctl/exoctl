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

        class LexerToken : public Exception::ExceptionBase
        {
          public:
            explicit LexerToken(const std::string &);
        };

        class IncludeSig : public Exception::ExceptionBase
        {
          public:
            explicit IncludeSig(const std::string &);
        };

        class SigRule : public Exception::ExceptionBase
        {
          public:
            explicit SigRule(const std::string &);
        };
    } // namespace SignaturesException
} // namespace Security