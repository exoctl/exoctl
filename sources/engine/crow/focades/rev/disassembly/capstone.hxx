#pragma once

#include <engine/crow/focades/rev/disassembly/capstone_types.hxx>
#include <engine/disassembly/capstone/capstone.hxx>
#include <engine/parser/json.hxx>

namespace Focades
{
    namespace Rev
    {
        namespace Disassembly
        {
            class Capstone
            {
              public:
                Capstone(const cs_arch, const cs_mode);
                ~Capstone();

                void capstone_disassembly(
                    const std::string &,
                    const std::function<void(Structs::DTO *)> &);

                ::Parser::Json capstone_dto_json(const Structs::DTO *);

              private:
                ::Disassembly::Capstone m_capstone;
                const std::string m_arch;
                const std::string m_mode;
            };
        } // namespace Disassembly
    } // namespace Rev
} // namespace Focades