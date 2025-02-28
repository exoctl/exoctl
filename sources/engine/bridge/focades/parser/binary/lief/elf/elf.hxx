#pragma once

#include <engine/parser/binary/lief/lief.hxx>
#include <engine/parser/json/json.hxx>
#include <engine/bridge/focades/parser/binary/lief/elf/entitys.hxx>

namespace engine
{
    namespace focades
    {
        namespace parser
        {
            namespace binary
            {
                class ELF
                {
                  public:
                    ELF();
                    ~ELF();

                    void parse_bytes(
                        const std::string &,
                        const std::function<void(binary::elf::record::DTO *)>
                            &);
                    const ::engine::parser::Json dto_json(
                        binary::elf::record::DTO *);

                  private:
                    ::engine::parser::binary::LIEF<const LIEF::ELF::Binary,
                                                   const LIEF::ELF::Parser>
                        m_elf;
                };
            } // namespace binary
        } // namespace parser
    } // namespace focades
} // namespace engine