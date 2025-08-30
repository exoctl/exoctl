#pragma once

#include <tlsh.h>
#include <string>

namespace engine
{
    namespace crypto
    {
        class Tlsh
        {
          public:
            Tlsh() = default;
            ~Tlsh() = default;

            [[nodiscard]] static const std::string hash(const std::string &);
            [[nodiscard]] static const int compare(const std::string &,
                               const std::string &);
        };
    } // namespace crypto
} // namespace engine