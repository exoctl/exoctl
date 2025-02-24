#pragma once

#include <engine/disassembly/capstone/capstone.hxx>
#include <engine/parser/json.hxx>
#include <engine/server/focades/reverse/disassembly/capstone/entitys.hxx>

namespace engine
{
    namespace focades
    {
        namespace reverse
        {
            namespace disassembly
            {
                class Capstone
                {
                  public:
                    Capstone(const cs_arch, const cs_mode);
                    ~Capstone() = default;

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
        } // namespace reverse
    } // namespace focades
} // namespace engine