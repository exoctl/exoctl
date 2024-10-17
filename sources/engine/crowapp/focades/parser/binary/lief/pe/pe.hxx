#pragma once

#include <engine/parser/binary/lief/lief.hxx>
#include <engine/parser/json.hxx>
#include <engine/crowapp/focades/parser/binary/lief/pe/entitys.hxx>

namespace engine
{
    namespace focades
    {
        namespace parser
        {
            namespace binary
            {
                class PE
                {
                  public:
                    PE();
                    ~PE();

                    void parser_bytes(
                        const std::string &,
                        const std::function<void(binary::pe::record::DTO *)> &);
                    const ::engine::parser::Json dto_json(
                        binary::pe::record::DTO *);

                  private:
                    ::engine::parser::binary::LIEF<const LIEF::PE::Binary,
                                                   const LIEF::PE::Parser>
                        m_pe;
                };
            } // namespace binary
        } // namespace parser
    } // namespace focades
} // namespace engine