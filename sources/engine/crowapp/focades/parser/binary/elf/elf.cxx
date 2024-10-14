#include "LIEF/ELF/DynamicEntry.hpp"
#include "LIEF/ELF/DynamicEntryFlags.hpp"
#include "LIEF/ELF/DynamicEntryLibrary.hpp"
#include "LIEF/json.hpp"
#include "fmt/format.h"
#include <engine/crowapp/focades/parser/binary/elf/elf.hxx>
#include <engine/memory.hxx>
#include <engine/parser/json.hxx>
#include <fmt/core.h>
#include <fmt/ranges.h>
#include <memory>

namespace engine
{
    namespace focades
    {
        namespace parser
        {
            namespace binary
            {
                ELF::ELF()
                {
                }
                ELF::~ELF()
                {
                }

                void ELF::parser_bytes(
                    const std::string &p_buffer,
                    const std::function<void(binary::elf::record::DTO *)>
                        &p_callback)
                {
                    m_elf.parser_file(
                        p_buffer,
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

                const ::engine::parser::Json ELF::dto_json(
                    binary::elf::record::DTO *p_dto)
                {
                    ::engine::parser::Json json;

                    if (!IS_NULL(p_dto)) {
                        json.from_string(LIEF::to_json(*p_dto->elf->get()));
                    }

                    return json;
                }

            } // namespace binary
        } // namespace parser
    } // namespace focades
} // namespace engine