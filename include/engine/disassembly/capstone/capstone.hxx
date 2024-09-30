#pragma once

#define CAPSTONE_AARCH64_COMPAT_HEADER

#include <capstone/capstone.h>
#include <engine/disassembly/capstone/capstone_types.hxx>
#include <functional>
#include <string>

namespace Disassembly
{
    class Capstone
    {
      public:
        Capstone(cs_arch, cs_mode);
        ~Capstone();

        void capstone_disassembly(
            const uint8_t *,
            size_t,
            const std::function<void(Struct::Data *, size_t)> &);

        [[nodiscard]] const cs_arch capstone_get_arch();
        [[nodiscard]] const cs_mode capstone_get_mode();
        [[nodiscard]] const std::string capstone_arch_to_string(const cs_arch);
        [[nodiscard]] const std::string capstone_mode_to_string(const cs_mode);

      private:
        csh m_handle;
        const cs_arch m_arch;
        const cs_mode m_mode;
    };
} // namespace Disassembly