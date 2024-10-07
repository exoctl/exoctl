#include <engine/parser/binary/elf.hxx>
#include <stdint.h>

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
            const std::function<void(std::unique_ptr<const LIEF::ELF::Binary>)>
                &p_callback)
        {
            p_callback(parse(std::vector<uint8_t>(p_buffer.begin(), p_buffer.end())));
        }

        void ELF::parser_file(
            const std::string &p_file_path,
            const std::function<void(std::unique_ptr<const LIEF::ELF::Binary>)>
                &p_callback)
        {
            p_callback(parse(p_file_path));
        }

    } // namespace Binary
} // namespace Parser