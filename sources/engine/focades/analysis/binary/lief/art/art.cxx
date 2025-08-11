#include <engine/focades/analysis/binary/lief/art/art.hxx>
#include <engine/memory/memory.hxx>
#include <engine/parser/json/json.hxx>

namespace engine::focades::analysis::binary::art
{

    void ART::parse_bytes(
        const std::string &p_buffer,
        const std::function<void(binary::art::record::DTO *)> &p_callback)
    {
        m_art.parse_bytes(p_buffer,
                          [&](std::unique_ptr<const LIEF::ART::File> p_art) {
                              if (p_art) {
                                  struct binary::art::record::DTO *dto =
                                      new binary::art::record::DTO;

                                  dto->art = &p_art;

                                  p_callback(dto);
                                  delete dto;
                              }
                          });
    }

    const ::engine::parser::Json ART::dto_json(binary::art::record::DTO *p_dto)
    {
        ::engine::parser::Json json;

        if (!IS_NULL(p_dto)) {
            json.from_string(LIEF::to_json(*p_dto->art->get()));
        }

        return json;
    }
} // namespace engine::focades::analysis::binary::art