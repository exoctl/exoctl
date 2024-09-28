/*
#include <engine/crow/focades/parser/elf.hxx>
#include <engine/parser/json.hxx>
#include <fmt/core.h>
#include <fmt/ranges.h>

namespace Focades
{
    namespace Parser
    {
        ELF::ELF()
        {
        }
        ELF::~ELF()
        {
        }

        void ELF::elf_parser_bytes(const std::string &p_buffer)
        {
            m_elf.elf_parser_file(
                p_buffer, [&](std::unique_ptr<const LIEF::ELF::Binary> p_elf) {
                    if (p_elf) {

                        dto_set_field("header", ELF::elf_header_json(p_elf));

                        ::Parser::Json dynamic_symbols;
                        for (const auto &symbol :
                             p_elf.get()->dynamic_symbols()) {
                            dynamic_symbols["name"] = symbol.name();
                            dynamic_symbols["type"] = symbol.type();

                            // elf.push_back(dynamic_symbols);
                        }
                    }
                });
        }

        ::Parser::Json ELF::elf_header_json(
            std::unique_ptr<const LIEF::ELF::Binary> &p_elf)
        {
            ::Parser::Json header;

            header["header"]["identity_version"] = fmt::format(
                "{:x}",
                static_cast<int>(p_elf.get()->header().identity_version()));
            header["header"]["file_type"] = fmt::format(
                "{:x}", static_cast<int>(p_elf.get()->header().file_type()));
            header["header"]["identity_abi_version"] = fmt::format(
                "{:x}", p_elf.get()->header().identity_abi_version());
            header["header"]["entrypoint"] =
                fmt::format("{:x}", p_elf.get()->entrypoint());
            header["header"]["program_headers_offset"] = fmt::format(
                "{:x}", p_elf.get()->header().program_headers_offset());
            header["header"]["section_headers_offset"] = fmt::format(
                "{:x}", p_elf.get()->header().section_headers_offset());
            header["header"]["numberof_segments"] =
                fmt::format("{:x}", p_elf.get()->header().numberof_segments());
            header["header"]["numberof_sections"] =
                fmt::format("{:x}", p_elf.get()->header().numberof_sections());
            header["header"]["section_name_table_idx"] = fmt::format(
                "{:x}", p_elf.get()->header().section_name_table_idx());
            header["header"]["program_header_size"] = fmt::format(
                "{:x}", p_elf.get()->header().program_header_size());
            header["header"]["section_header_size"] = fmt::format(
                "{:x}", p_elf.get()->header().section_header_size());
            header["header"]["identity_data"] = fmt::format(
                "{:x}",
                static_cast<int>(p_elf.get()->header().identity_data()));
            header["header"]["abstract_endianness"] = fmt::format(
                "{:x}",
                static_cast<int>(p_elf.get()->header().abstract_endianness()));
            header["header"]["header_size"] =
                fmt::format("{:x}", p_elf.get()->header().header_size());

            header["header"]["identity"] = fmt::format(
                "{:x}", fmt::join(p_elf.get()->header().identity(), " "));

            return header;
        }
    } // namespace Parser
} // namespace Focades

*/