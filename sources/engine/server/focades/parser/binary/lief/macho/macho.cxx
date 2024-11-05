#include <engine/server/focades/parser/binary/lief/macho/macho.hxx>
#include <engine/memory/memory.hxx>
#include <engine/parser/json.hxx>

namespace engine
{
    namespace focades
    {
        namespace parser
        {
            namespace binary
            {
                MACHO::MACHO()
                {
                }

                MACHO::~MACHO()
                {
                }
                
                void MACHO::parse_bytes(
                    const std::string &p_buffer,
                    const std::function<void(binary::macho::record::DTO *)>
                        &p_callback)
                {
                    m_macho.parse_bytes(
                        p_buffer,
                        [&](std::unique_ptr<const LIEF::MachO::FatBinary>
                                p_macho) {
                            if (p_macho) {
                                struct binary::macho::record::DTO *dto =
                                    new binary::macho::record::DTO;

                                dto->macho = &p_macho;

                                p_callback(dto);
                                delete dto;
                            }
                        });
                }

                const ::engine::parser::Json MACHO::dto_json(
                    binary::macho::record::DTO *p_dto)
                {
                    ::engine::parser::Json json;

                    if (!IS_NULL(p_dto)) {
                        json.from_string(
                            LIEF::to_json(*p_dto->macho->get()->back()));
                    }

                    return json;
                }

            } // namespace binary
        } // namespace parser
    } // namespace focades
} // namespace engine
