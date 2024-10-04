#pragma once

#include <engine/exception.hxx>
#include <string>

namespace security
{
    namespace yara
    {
        namespace exception
        {
            class CompilerRules : public ::exception::Exception
            {
              public:
                explicit CompilerRules(const std::string &);
            };

            class LoadRules : public ::exception::Exception
            {
              public:
                explicit LoadRules(const std::string &);
            };

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

            class Scan : public ::exception::Exception
            {
              public:
                explicit Scan(const std::string &);
            };

        } // namespace exception
    } // namespace yara
} // namespace security