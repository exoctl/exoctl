#include <engine/parser/elf.hxx>

namespace Parser
{
Elf::Elf() {}
Elf::~Elf() {}

const std::unique_ptr<const LIEF::ELF::Binary>
Elf::elf_parser_buffer(const std::string &p_buffer)
{
    
    return nullptr;
}

const std::unique_ptr<const LIEF::ELF::Binary>
Elf::elf_parser_file(const std::string &)
{
    return nullptr;
}

} // namespace Parser