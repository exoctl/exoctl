#include <engine/bridge/focades/parser/binary/lief/elf/elf.hxx>
#include <engine/memory/memory.hxx>
#include <engine/parser/json/json.hxx>

namespace engine::bridge::focades::parser::binary::elf
{

    void ELF::parse_bytes(
        const std::string &p_buffer,
        const std::function<void(binary::elf::record::DTO *)> &p_callback)
    {
        m_elf.parse_bytes(p_buffer,
                          [&](std::unique_ptr<const LIEF::ELF::Binary> p_elf) {
                              if (p_elf) {
                                  struct binary::elf::record::DTO *dto =
                                      new binary::elf::record::DTO;

                                  dto->elf = &p_elf;

                                  p_callback(dto);
                                  delete dto;
                              }
                          });
    }

    const ::engine::parser::Json ELF::dto_json(binary::elf::record::DTO *p_dto)
    {
        ::engine::parser::Json json;

        if (!IS_NULL(p_dto)) {
            json.from_string(LIEF::to_json(*p_dto->elf->get()));
        }

        return json;
    }
} // namespace engine::bridge::focades::parser::binary::elf