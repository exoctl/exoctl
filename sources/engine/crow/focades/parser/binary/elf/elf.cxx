#include <engine/crow/focades/parser/binary/elf/elf.hxx>
#include <engine/parser/json.hxx>
#include <fmt/core.h>
#include <fmt/ranges.h>

namespace Focades
{
    namespace Parser
    {
        namespace Binary
        {
            ELF::ELF()
            {
            }
            ELF::~ELF()
            {
            }

            void ELF::elf_parser_bytes(
                const std::string &p_buffer,
                const std::function<void(Structs::DTO *)> &p_callback)
            {
                m_elf.elf_parser_file(
                    p_buffer,
                    [&](std::unique_ptr<const LIEF::ELF::Binary> p_elf) {
                        if (p_elf) {
                            struct Structs::DTO *dto = new Structs::DTO;

                            dto->header = p_elf.get()->header();

                            p_callback(dto);
                            delete dto;
                        }
                    });
            }
            const ::Parser::Json ELF::elf_dto_json(Structs::DTO *p_dto)
            {
                ::Parser::Json elf;

                elf.json_add_member_json("header", ELF::elf_header_json(p_dto));

                return elf;
            }

            ::Parser::Json ELF::elf_header_json(Structs::DTO *p_dto)
            {
                ::Parser::Json header;

                header.json_add_member_string(
                    "identity_version",
                    fmt::format(
                        "{:x}",
                        static_cast<int>(p_dto->header.identity_version())));
                header.json_add_member_string(
                    "file_type",
                    fmt::format("{:x}",
                                static_cast<int>(p_dto->header.file_type())));
                header.json_add_member_string(
                    "identity_abi_version",
                    fmt::format("{:x}",
                                p_dto->header.identity_abi_version()));
                header.json_add_member_string(
                    "entrypoint", fmt::format("{:x}", p_dto->header.entrypoint()));
                header.json_add_member_string(
                    "program_headers_offset",
                    fmt::format("{:x}",
                                p_dto->header.program_headers_offset()));
                header.json_add_member_string(
                    "section_headers_offset",
                    fmt::format("{:x}",
                                p_dto->header.section_headers_offset()));
                header.json_add_member_string(
                    "numberof_segments",
                    fmt::format("{:x}", p_dto->header.numberof_segments()));
                header.json_add_member_string(
                    "numberof_sections",
                    fmt::format("{:x}", p_dto->header.numberof_sections()));
                header.json_add_member_string(
                    "section_name_table_idx",
                    fmt::format("{:x}",
                                p_dto->header.section_name_table_idx()));
                header.json_add_member_string(
                    "program_header_size",
                    fmt::format("{:x}", p_dto->header.program_header_size()));
                header.json_add_member_string(
                    "section_header_size",
                    fmt::format("{:x}", p_dto->header.section_header_size()));
                header.json_add_member_string(
                    "identity_data",
                    fmt::format(
                        "{:x}",
                        static_cast<int>(p_dto->header.identity_data())));
                header.json_add_member_string(
                    "abstract_endianness",
                    fmt::format("{:x}",
                                static_cast<int>(
                                    p_dto->header.abstract_endianness())));
                header.json_add_member_string(
                    "header_size",
                    fmt::format("{:x}", p_dto->header.header_size()));
                header.json_add_member_string(
                    "identity",
                    fmt::format("{:x}",
                                fmt::join(p_dto->header.identity(), " ")));

                // Adiciona o objeto "header" como um membro "header" no
                // JSON principal
                header.json_add_member_json("header", header);

                return header;
            }
        } // namespace Binary
    } // namespace Parser
} // namespace Focades