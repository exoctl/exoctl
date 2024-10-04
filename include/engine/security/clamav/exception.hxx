#pragma once

#include <engine/exception.hxx>

namespace security
{
    namespace clamav
    {
        namespace exception
        {
            class Initialize : public ::exception::Exception
            {
              public:
                explicit Initialize(const std::string &);
            };

            class LoadRules : public ::exception::Exception
            {
              public:
                explicit LoadRules(const std::string &);
            };

            class SetDbRules : public ::exception::Exception
            {
              public:
                explicit SetDbRules(const std::string &);
            };
        } // namespace exception
    } // namespace clamav
} // namespace security