#include <LIEF/LIEF.hpp>

namespace Parser
{
class Elf : public LIEF::ELF::Binary
{
  public:
    Elf();
    ~Elf();

    const std::unique_ptr<const LIEF::ELF::Binary>
    elf_parser_buffer(const std::string &);

    const std::unique_ptr<const LIEF::ELF::Binary>
    elf_parser_file(const std::string &);
};
} // namespace Parser