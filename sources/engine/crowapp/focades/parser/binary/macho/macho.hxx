#pragma once

#include <engine/crowapp/focades/parser/binary/macho/entitys.hxx>
#include <engine/parser/binary/macho.hxx>
#include <engine/parser/json.hxx>

namespace engine
{
    namespace focades
    {
        namespace parser
        {
            namespace binary
            {
                class MACHO
                {
                  public:
                    MACHO();
                    ~MACHO();

                    void parser_bytes(
                        const std::string &,
                        const std::function<void(binary::macho::record::DTO *)>
                            &);
                    const ::engine::parser::Json dto_json(
                        binary::macho::record::DTO *);

                  private:
                    ::engine::parser::binary::MACHO m_macho;
                };
            } // namespace binary
        } // namespace parser
    } // namespace focades
} // namespace engine