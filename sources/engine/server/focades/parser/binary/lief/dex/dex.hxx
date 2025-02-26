#pragma once

#include <engine/parser/binary/lief/lief.hxx>
#include <engine/parser/json/json.hxx>
#include <engine/server/focades/parser/binary/lief/dex/entitys.hxx>

namespace engine
{
    namespace focades
    {
        namespace parser
        {
            namespace binary
            {
                class DEX
                {
                  public:
                    DEX();
                    ~DEX();

                    void parse_bytes(
                        const std::string &,
                        const std::function<void(binary::dex::record::DTO *)>
                            &);
                    const ::engine::parser::Json dto_json(
                        binary::dex::record::DTO *);

                  private:
                    ::engine::parser::binary::LIEF<const LIEF::DEX::File,
                                                   const LIEF::DEX::Parser>
                        m_dex;
                };
            } // namespace binary
        } // namespace parser
    } // namespace focades
} // namespace engine