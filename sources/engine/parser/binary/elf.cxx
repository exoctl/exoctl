#include <engine/parser/binary/elf.hxx>

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

        std::unique_ptr<const LIEF::ELF::Binary> &ELF::elf_parser_buffer(
            const std::string &p_buffer)
        {
            m_elf = LIEF::ELF::Parser::parse(
                std::vector<uint8_t>(p_buffer.begin(), p_buffer.end()));

            return m_elf;
        }

        std::unique_ptr<const LIEF::ELF::Binary> &ELF::elf_parser_file(
            const std::string &p_file_path)
        {
            m_elf = LIEF::ELF::Parser::parse(p_file_path);

            return m_elf;
        }
    } // namespace Binary
} // namespace Parser