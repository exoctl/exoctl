#include <engine/crowapp/focades/parser/binary/elf/elf.hxx>
#include <engine/memory.hxx>
#include <engine/parser/json.hxx>
#include <fmt/core.h>
#include <fmt/ranges.h>

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

            void ELF::elf_parser_bytes(
                const std::string &p_buffer,
                const std::function<void(binary::elf::record::DTO *)>
                    &p_callback)
            {
                m_elf.elf_parser_file(
                    p_buffer,
                    [&](std::unique_ptr<const LIEF::ELF::Binary> p_elf) {
                        if (p_elf) {
                            struct binary::elf::record::DTO *dto =
                                new binary::elf::record::DTO;

                            dto->elf_header = p_elf.get()->header();

                            p_callback(dto);
                            delete dto;
                        }
                    });
            }
            const ::parser::Json ELF::elf_dto_json(
                binary::elf::record::DTO *p_dto)
            {
                ::parser::Json elf;
                
                if (!IS_NULL(p_dto)) {

                    elf.json_add_member_json("header",
                                             ELF::elf_header_json(p_dto));
                }

                return elf;
            }

            ::parser::Json ELF::elf_header_json(binary::elf::record::DTO *p_dto)
            {
                ::parser::Json header;

                header.json_add_member_string(
                    "identity_version",
                    fmt::format(
                        "{:x}",
                        static_cast<int>(p_dto->elf_header.identity_version())));
                header.json_add_member_string(
                    "file_type",
                    fmt::format("{:x}",
                                static_cast<int>(p_dto->elf_header.file_type())));
                header.json_add_member_string(
                    "identity_abi_version",
                    fmt::format("{:x}", p_dto->elf_header.identity_abi_version()));
                header.json_add_member_string(
                    "entrypoint",
                    fmt::format("{:x}", p_dto->elf_header.entrypoint()));
                header.json_add_member_string(
                    "program_headers_offset",
                    fmt::format("{:x}",
                                p_dto->elf_header.program_headers_offset()));
                header.json_add_member_string(
                    "section_headers_offset",
                    fmt::format("{:x}",
                                p_dto->elf_header.section_headers_offset()));
                header.json_add_member_string(
                    "numberof_segments",
                    fmt::format("{:x}", p_dto->elf_header.numberof_segments()));
                header.json_add_member_string(
                    "numberof_sections",
                    fmt::format("{:x}", p_dto->elf_header.numberof_sections()));
                header.json_add_member_string(
                    "section_name_table_idx",
                    fmt::format("{:x}",
                                p_dto->elf_header.section_name_table_idx()));
                header.json_add_member_string(
                    "program_header_size",
                    fmt::format("{:x}", p_dto->elf_header.program_header_size()));
                header.json_add_member_string(
                    "section_header_size",
                    fmt::format("{:x}", p_dto->elf_header.section_header_size()));
                header.json_add_member_string(
                    "identity_data",
                    fmt::format(
                        "{:x}",
                        static_cast<int>(p_dto->elf_header.identity_data())));
                header.json_add_member_string(
                    "abstract_endianness",
                    fmt::format(
                        "{:x}",
                        static_cast<int>(p_dto->elf_header.abstract_endianness())));
                header.json_add_member_string(
                    "header_size",
                    fmt::format("{:x}", p_dto->elf_header.header_size()));
                header.json_add_member_string(
                    "identity",
                    fmt::format("{:x}",
                                fmt::join(p_dto->elf_header.identity(), " ")));

                return header;
            }
        } // namespace binary
    } // namespace parser
} // namespace focades