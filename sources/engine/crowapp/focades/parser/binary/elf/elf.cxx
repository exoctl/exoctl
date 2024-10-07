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

                            p_callback(dto);
                            delete dto;
                        }
                    });
            }
            const ::parser::Json ELF::dto_json(
                binary::elf::record::DTO *p_dto)
            {
                ::parser::Json elf;
                
                if (!IS_NULL(p_dto)) {

                    elf.add_member_json("header",
                                             ELF::header_json(p_dto));
                }

                return elf;
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