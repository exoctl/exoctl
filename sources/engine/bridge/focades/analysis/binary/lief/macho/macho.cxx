#include <engine/bridge/focades/analysis/binary/lief/macho/macho.hxx>
#include <engine/memory/memory.hxx>
#include <engine/parser/binary/lief/exception.hxx>
#include <engine/parser/json/json.hxx>

namespace engine::bridge::focades::analysis::binary::macho
{
    void MACHO::parse_bytes(
        const std::string &p_buffer,
        const std::function<void(binary::macho::record::DTO *)> &p_callback)
    {
        m_macho.parse_bytes(
            p_buffer,
            [&](std::unique_ptr<const LIEF::MachO::FatBinary> p_macho) {
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
            json.from_string(LIEF::to_json(*p_dto->macho->get()->back()));
        }

        return json;
    }
} // namespace engine::bridge::focades::analysis::binary::macho