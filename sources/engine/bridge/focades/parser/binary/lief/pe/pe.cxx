#include <engine/bridge/focades/parser/binary/lief/pe/pe.hxx>
#include <engine/memory/memory.hxx>
#include <engine/parser/json/json.hxx>

namespace engine::bridge::focades::parser::binary::pe
{
    void PE::parse_bytes(
        const std::string &p_buffer,
        const std::function<void(binary::pe::record::DTO *)> &p_callback)
    {
        m_pe.parse_bytes(p_buffer,
                         [&](std::unique_ptr<const LIEF::PE::Binary> p_pe) {
                             if (p_pe) {
                                 struct binary::pe::record::DTO *dto =
                                     new binary::pe::record::DTO;

                                 dto->pe = &p_pe;

                                 p_callback(dto);
                                 delete dto;
                             }
                         });
    }

    const ::engine::parser::Json PE::dto_json(binary::pe::record::DTO *p_dto)
    {
        ::engine::parser::Json json;

        if (!IS_NULL(p_dto)) {
            json.from_string(LIEF::to_json(*p_dto->pe->get()));
        }

        return json;
    }

} // namespace engine::bridge::focades::parser::binary::pe
