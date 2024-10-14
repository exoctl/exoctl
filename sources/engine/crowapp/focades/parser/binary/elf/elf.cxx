#include "LIEF/ELF/DynamicEntry.hpp"
#include "LIEF/ELF/DynamicEntryFlags.hpp"
#include "LIEF/ELF/DynamicEntryLibrary.hpp"
#include "fmt/format.h"
#include <engine/crowapp/focades/parser/binary/elf/elf.hxx>
#include <engine/memory.hxx>
#include <engine/parser/json.hxx>
#include <fmt/core.h>
#include <fmt/ranges.h>

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

                                dto->header = p_elf.get()->header();

                                dto->sections.reserve(
                                    p_elf.get()->sections().size());
                                std::move(p_elf.get()->sections().begin(),
                                          p_elf.get()->sections().end(),
                                          std::back_inserter(dto->sections));

                                dto->dynamic_entries.reserve(
                                    p_elf.get()->dynamic_entries().size());
                                std::move(
                                    p_elf.get()->dynamic_entries().begin(),
                                    p_elf.get()->dynamic_entries().end(),
                                    std::back_inserter(dto->dynamic_entries));

                                dto->segments.reserve(
                                    p_elf.get()->segments().size());
                                std::move(p_elf.get()->segments().begin(),
                                          p_elf.get()->segments().end(),
                                          std::back_inserter(dto->segments));

                                dto->symbols.reserve(
                                    p_elf.get()->symbols().size());
                                std::move(p_elf.get()->symbols().begin(),
                                          p_elf.get()->symbols().end(),
                                          std::back_inserter(dto->symbols));

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

                        json.add_member_json("header", ELF::header_json(p_dto));
                        json.add_member_vector("sections",
                                               ELF::sections_json(p_dto));
                        json.add_member_vector("segments",
                                               ELF::segments_json(p_dto));
                        json.add_member_vector(
                            "dynamic_entries",
                            ELF::dynamic_entries_json(p_dto));

                        json.add_member_vector("symbols",
                                               ELF::symbols_json(p_dto));
                    }

                    return json;
                }

                std::vector<::engine::parser::Json> ELF::symbols_json(
                    binary::elf::record::DTO *p_dto)
                {
                    std::vector<::engine::parser::Json> symbols;
                    symbols.reserve(p_dto->symbols.size());

                    for (const auto &symbol : p_dto->symbols) {
                        ::engine::parser::Json sym;

                        sym.add_member_string("name", symbol.name());
                        sym.add_member_string("demangled_name",
                                              symbol.demangled_name());
                        sym.add_member_bool("has_version",
                                            symbol.has_version());
                        sym.add_member_bool("is_static", symbol.is_static());
                        sym.add_member_bool("is_variable",
                                            symbol.is_variable());
                        sym.add_member_bool("is_weak", symbol.is_weak());
                        sym.add_member_bool("symbol_version",
                                            symbol.symbol_version());
                        sym.add_member_string(
                            "type", LIEF::ELF::to_string(symbol.type()));
                        sym.add_member_bool("is_global", symbol.is_global());
                        sym.add_member_bool("is_local", symbol.is_local());
                        sym.add_member_bool("is_imported",
                                            symbol.is_imported());
                        sym.add_member_string(
                            "visibility",
                            LIEF::ELF::to_string(symbol.visibility()));
                        sym.add_member_string(
                            "binding", LIEF::ELF::to_string(symbol.binding()));
                        sym.add_member_string(
                            "size", fmt::format("{:x}", symbol.size()));
                        sym.add_member_string(
                            "shndx", fmt::format("{:x}", symbol.shndx()));
                        sym.add_member_string(
                            "value", fmt::format("{:x}", symbol.value()));

                        symbols.push_back(sym);
                    }

                    return symbols;
                }

                std::vector<::engine::parser::Json> ELF::segments_json(
                    binary::elf::record::DTO *p_dto)
                {
                    std::vector<::engine::parser::Json> segments;
                    segments.reserve(p_dto->segments.size());

                    for (const auto &segment : p_dto->segments) {
                        ::engine::parser::Json seg;
                        seg.add_member_string(
                            "virtual_address",
                            fmt::format("{:x}", segment.virtual_address()));
                        seg.add_member_string(
                            "virtual_size",
                            fmt::format("{:x}", segment.virtual_size()));
                        seg.add_member_string(
                            "type",
                            fmt::format("{:x}",
                                        static_cast<uint32_t>(segment.type())));
                        seg.add_member_string(
                            "flags",
                            fmt::format(
                                "{:x}",
                                static_cast<uint32_t>(segment.flags())));
                        seg.add_member_string(
                            "physical_size",
                            fmt::format("{:x}", segment.physical_size()));
                        seg.add_member_string(
                            "physical_address",
                            fmt::format("{:x}", segment.physical_address()));
                        seg.add_member_string(
                            "alignment",
                            fmt::format("{:x}", segment.alignment()));
                        seg.add_member_string(
                            "file_offset",
                            fmt::format("{:x}", segment.file_offset()));
                        seg.add_member_string(
                            "content",
                            fmt::format("{}",
                                        fmt::join(segment.content().data(),
                                                  segment.content().data() +
                                                      segment.content().size(),
                                                  "")));

                        segments.push_back(seg);
                    }

                    return segments;
                }

                std::vector<::engine::parser::Json> ELF::sections_json(
                    binary::elf::record::DTO *p_dto)
                {
                    std::vector<::engine::parser::Json> sections;
                    sections.reserve(p_dto->sections.size());

                    for (const auto &section : p_dto->sections) {
                        ::engine::parser::Json sec;
                        sec.add_member_string("name", section.name());
                        sec.add_member_string(
                            "virtual_address",
                            fmt::format("{:x}", section.virtual_address()));
                        sec.add_member_string(
                            "offset", fmt::format("{:x}", section.offset()));
                        sec.add_member_string(
                            "size", fmt::format("{:x}", section.size()));

                        sections.push_back(sec);
                    }

                    return sections;
                }

                ::engine::parser::Json ELF::header_json(
                    binary::elf::record::DTO *p_dto)
                {
                    ::engine::parser::Json header;

                    header.add_member_string(
                        "identity_version",
                        fmt::format("{:x}",
                                    static_cast<int>(
                                        p_dto->header.identity_version())));
                    header.add_member_string(
                        "file_type",
                        fmt::format(
                            "{:x}",
                            static_cast<int>(p_dto->header.file_type())));
                    header.add_member_string(
                        "identity_abi_version",
                        fmt::format("{:x}",
                                    p_dto->header.identity_abi_version()));
                    header.add_member_string(
                        "entrypoint",
                        fmt::format("{:x}", p_dto->header.entrypoint()));
                    header.add_member_string(
                        "program_headers_offset",
                        fmt::format("{:x}",
                                    p_dto->header.program_headers_offset()));
                    header.add_member_string(
                        "section_headers_offset",
                        fmt::format("{:x}",
                                    p_dto->header.section_headers_offset()));
                    header.add_member_string(
                        "numberof_segments",
                        fmt::format("{:x}", p_dto->header.numberof_segments()));
                    header.add_member_string(
                        "numberof_sections",
                        fmt::format("{:x}", p_dto->header.numberof_sections()));
                    header.add_member_string(
                        "section_name_table_idx",
                        fmt::format("{:x}",
                                    p_dto->header.section_name_table_idx()));
                    header.add_member_string(
                        "program_header_size",
                        fmt::format("{:x}",
                                    p_dto->header.program_header_size()));
                    header.add_member_string(
                        "section_header_size",
                        fmt::format("{:x}",
                                    p_dto->header.section_header_size()));
                    header.add_member_string(
                        "identity_data",
                        fmt::format(
                            "{:x}",
                            static_cast<int>(p_dto->header.identity_data())));
                    header.add_member_string(
                        "abstract_endianness",
                        fmt::format("{:x}",
                                    static_cast<int>(
                                        p_dto->header.abstract_endianness())));
                    header.add_member_string(
                        "header_size",
                        fmt::format("{:x}", p_dto->header.header_size()));
                    header.add_member_string(
                        "identity",
                        fmt::format("{:x}",
                                    fmt::join(p_dto->header.identity(), " ")));

                    return header;
                }

                std::vector<::engine::parser::Json> ELF::dynamic_entries_json(
                    binary::elf::record::DTO *p_dto)
                {
                    std::vector<::engine::parser::Json> dynamic_entries;
                    dynamic_entries.reserve(p_dto->dynamic_entries.size());

                    for (auto &entry : p_dto->dynamic_entries) {
                        ::engine::parser::Json dyn;

                        dyn.add_member_uint64("tag", entry.value());
                        dyn.add_member_string(
                            "type", LIEF::ELF::to_string(entry.tag()));

                        dynamic_entries.push_back(dyn);
                    }

                    return dynamic_entries;
                }

            } // namespace binary
        } // namespace parser
    } // namespace focades
} // namespace engine