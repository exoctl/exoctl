#include <engine/parser/elf.hxx>

namespace Parser
{
    Elf::Elf()
    {
    }
    Elf::~Elf()
    {
    }

    const std::unique_ptr<const LIEF::ELF::Binary> Elf::elf_parser_buffer(
        const std::string &p_buffer)
    {
        std::unique_ptr<LIEF::ELF::Binary> elf = LIEF::ELF::Parser::parse(
            std::vector<uint8_t>(p_buffer.begin(), p_buffer.end()));

        if (!elf)
            return nullptr;

        return elf;
    }

    const std::unique_ptr<const LIEF::ELF::Binary> Elf::elf_parser_file(
        const std::string &p_file_path)
    {
        std::unique_ptr<const LIEF::ELF::Binary> elf =
            LIEF::ELF::Parser::parse(p_file_path);

        if (!elf)
            return nullptr;

        return elf;
    }

} // namespace Parser