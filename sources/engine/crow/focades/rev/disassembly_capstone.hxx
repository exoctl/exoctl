#pragma once

#include <engine/crow/focades/rev/disassembly_capstone_types.hxx>
#include <engine/disassembly/capstone/capstone.hxx>

namespace Focades
{
    namespace Rev
    {
        class Capstone
        {
          public:
            Capstone(const cs_arch, const cs_mode);
            ~Capstone();

            void capstone_disassembly(
                const std::string &,
                const std::function<void(Structs::DTO *)> &);

          private:
            Disassembly::Capstone m_capstone;
            std::string m_arch, m_mode;
        };
    } // namespace Rev
} // namespace Focades