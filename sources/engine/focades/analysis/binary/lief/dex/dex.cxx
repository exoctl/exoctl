#include <engine/focades/analysis/binary/lief/dex/dex.hxx>
#include <engine/memory/memory.hxx>
#include <engine/parser/json/json.hxx>

namespace engine::focades::analysis::binary::dex
{
    void DEX::parse_bytes(
        const std::string &p_buffer,
        const std::function<void(binary::dex::record::DTO *)> &p_callback)
    {
        dex_.parse_bytes(p_buffer,
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

    const ::engine::parser::json::Json DEX::dto_json(binary::dex::record::DTO *p_dto)
    {
        ::engine::parser::json::Json json;

        if (!IS_NULL(p_dto)) {
            json.from_string(LIEF::to_json(*p_dto->dex->get()));
        }

        return json;
    }

} // namespace engine::focades::analysis::binary::dex