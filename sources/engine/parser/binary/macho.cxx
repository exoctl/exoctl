#include <engine/parser/binary/macho.hxx>
#include <stdint.h>

namespace engine
{
    namespace parser
    {
        namespace binary
        {
            MACHO::MACHO()
            {
            }
            MACHO::~MACHO()
            {
            }

            void MACHO::parser_bytes(
                const std::string &p_buffer,
                const std::function<void(
                    std::unique_ptr<const LIEF::MachO::FatBinary>)> &p_callback)
            {
                p_callback(LIEF::MachO::Parser::parse(
                    std::vector<uint8_t>(p_buffer.begin(), p_buffer.end())));
            }

            void MACHO::parser_file(
                const std::string &p_file_path,
                const std::function<void(
                    std::unique_ptr<const LIEF::MachO::FatBinary>)> &p_callback)
            {
                p_callback(LIEF::MachO::Parser::parse(p_file_path));
            }
        } // namespace binary
    } // namespace parser
} // namespace engine