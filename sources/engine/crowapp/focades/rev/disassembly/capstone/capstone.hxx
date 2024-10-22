#pragma once

#include <engine/crowapp/focades/rev/disassembly/capstone/entitys.hxx>
#include <engine/disassembly/capstone/capstone.hxx>
#include <engine/parser/json.hxx>

namespace engine
{
    namespace focades
    {
        namespace rev
        {
            namespace disassembly
            {
                class Capstone
                {
                  public:
                    Capstone(const cs_arch, const cs_mode);
                    ~Capstone();

                    void disassembly(
                        const std::string &,
                        const std::function<void(capstone::record::DTO *)> &);

                    ::engine::parser::Json dto_json(
                        const capstone::record::DTO *);

                  private:
                    ::engine::disassembly::Capstone m_capstone;
                    const std::string m_arch;
                    const std::string m_mode;
                };
            } // namespace disassembly
        } // namespace rev
    } // namespace focades
} // namespace engine