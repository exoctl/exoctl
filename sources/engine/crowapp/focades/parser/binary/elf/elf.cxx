#include <engine/crowapp/focades/parser/binary/elf/elf.hxx>
#include <engine/memory.hxx>
#include <engine/parser/json.hxx>
#include <fmt/core.h>
#include <fmt/ranges.h>
#include <span>

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

                            dto->segments.reserve(
                                p_elf.get()->segments().size());
                            std::move(p_elf.get()->segments().begin(),
                                      p_elf.get()->segments().end(),
                                      std::back_inserter(dto->segments));

                            p_callback(dto);
                            delete dto;
                        }
                    });
            }

            const ::parser::Json ELF::dto_json(binary::elf::record::DTO *p_dto)
            {
                ::parser::Json elf;

                if (!IS_NULL(p_dto)) {

                    elf.add_member_json("header", ELF::header_json(p_dto));
                    elf.add_member_vector("sections",
                                          ELF::sections_json(p_dto));
                    elf.add_member_vector("segments",
                                          ELF::segments_json(p_dto));
                }

                return elf;
            }

            std::vector<::parser::Json> ELF::segments_json(
                binary::elf::record::DTO *p_dto)
            {
                std::vector<::parser::Json> segments;

                for (const auto &segment : p_dto->segments) {
                    ::parser::Json seg;
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
                        fmt::format("{:x}",
                                    static_cast<uint32_t>(segment.flags())));
                    seg.add_member_string(
                        "physical_size",
                        fmt::format("{:x}", segment.physical_size()));
                    seg.add_member_string(
                        "physical_address",
                        fmt::format("{:x}", segment.physical_address()));
                    seg.add_member_string(
                        "alignment", fmt::format("{:x}", segment.alignment()));
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

            std::vector<::parser::Json> ELF::sections_json(
                binary::elf::record::DTO *p_dto)
            {
                std::vector<::parser::Json> sections;

                for (const auto &section : p_dto->sections) {
                    ::parser::Json sec;
                    sec.add_member_string("name", section.name());
                    sec.add_member_string(
                        "virtual_address",
                        fmt::format("{:x}", section.virtual_address()));
                    sec.add_member_string(
                        "offset", fmt::format("{:x}", section.offset()));
                    sec.add_member_string("size",
                                          fmt::format("{:x}", section.size()));

                    sections.push_back(sec);
                }

                return sections;
            }

            ::parser::Json ELF::header_json(binary::elf::record::DTO *p_dto)
            {
                ::parser::Json header;

                header.add_member_string(
                    "identity_version",
                    fmt::format(
                        "{:x}",
                        static_cast<int>(p_dto->header.identity_version())));
                header.add_member_string(
                    "file_type",
                    fmt::format("{:x}",
                                static_cast<int>(p_dto->header.file_type())));
                header.add_member_string(
                    "identity_abi_version",
                    fmt::format("{:x}", p_dto->header.identity_abi_version()));
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
                    fmt::format("{:x}", p_dto->header.program_header_size()));
                header.add_member_string(
                    "section_header_size",
                    fmt::format("{:x}", p_dto->header.section_header_size()));
                header.add_member_string(
                    "identity_data",
                    fmt::format(
                        "{:x}",
                        static_cast<int>(p_dto->header.identity_data())));
                header.add_member_string(
                    "abstract_endianness",
                    fmt::format(
                        "{:x}",
                        static_cast<int>(p_dto->header.abstract_endianness())));
                header.add_member_string(
                    "header_size",
                    fmt::format("{:x}", p_dto->header.header_size()));
                header.add_member_string(
                    "identity",
                    fmt::format("{:x}",
                                fmt::join(p_dto->header.identity(), " ")));

                return header;
            }
        } // namespace binary
    } // namespace parser
} // namespace focades