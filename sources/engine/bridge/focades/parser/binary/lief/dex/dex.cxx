#include <engine/bridge/focades/parser/binary/lief/dex/dex.hxx>
#include <engine/memory/memory.hxx>
#include <engine/parser/json/json.hxx>

namespace engine::bridge::focades::parser::binary::dex
{
    void DEX::parse_bytes(
        const std::string &p_buffer,
        const std::function<void(binary::dex::record::DTO *)> &p_callback)
    {
        m_dex.parse_bytes(p_buffer,
                          [&](std::unique_ptr<const LIEF::DEX::File> p_dex) {
                              if (p_dex) {
                                  struct binary::dex::record::DTO *dto =
                                      new binary::dex::record::DTO;

                                  dto->dex = &p_dex;
                                  p_callback(dto);

                                  delete dto;
                              }
                          });
    }

    const ::engine::parser::Json DEX::dto_json(binary::dex::record::DTO *p_dto)
    {
        ::engine::parser::Json json;

        if (!IS_NULL(p_dto)) {
            json.from_string(LIEF::to_json(*p_dto->dex->get()));
        }

        return json;
    }

} // namespace engine::bridge::focades::parser::binary::dex