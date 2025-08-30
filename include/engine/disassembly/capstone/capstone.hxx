#pragma once

#define CAPSTONE_AARCH64_COMPAT_HEADER

#include <capstone/capstone.h>
#include <engine/disassembly/capstone/entitys.hxx>
#include <functional>
#include <stdint.h>
#include <string>

namespace engine
{
    namespace disassembly
    {
        class Capstone
        {
          public:
            Capstone() = default;
            void setup(const cs_arch, const cs_mode);
            ~Capstone();

            void disassembly(
                const uint8_t *,
                size_t,
                const std::function<void(capstone::record::Data *, size_t)> &);

            [[nodiscard]] const cs_arch get_arch();
            [[nodiscard]] const cs_mode get_mode();
            [[nodiscard]] const std::string arch_to_string(const cs_arch);
            [[nodiscard]] const std::string mode_to_string(const cs_mode);

          private:
            csh handle_;
            cs_arch arch_;
            cs_mode mode_;
        };
    } // namespace disassembly
} // namespace engine