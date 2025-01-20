#pragma once

#include <engine/parser/binary/lief/lief.hxx>
#include <engine/parser/json.hxx>
#include <engine/server/focades/parser/binary/lief/art/entitys.hxx>

namespace engine
{
    namespace focades
    {
        namespace parser
        {
            namespace binary
            {
                class ART
                {
                  public:
                    ART();
                    ~ART();

                    void parse_bytes(
                        const std::string &,
                        const std::function<void(binary::art::record::DTO *)>
                            &);
                    const ::engine::parser::Json dto_json(
                        binary::art::record::DTO *);

                  private:
                    ::engine::parser::binary::LIEF<const LIEF::ART::File,
                                                   const LIEF::ART::Parser>
                        m_art;
                };
            } // namespace binary
        } // namespace parser
    } // namespace focades
} // namespace engine