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
            Capstone(cs_arch, cs_mode);
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
            csh m_handle;
            const cs_arch m_arch;
            const cs_mode m_mode;
        };
    } // namespace disassembly
} // namespace engine