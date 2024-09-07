#pragma once

#include <engine/dto.hxx>
#include <include/engine/disassembly/capstone/capstone.hxx>

namespace Rev
{
class CapstoneX86 : public DTO::DTOBase
{
  public:
    CapstoneX86();
    ~CapstoneX86();

    void capstonex86_disassembly(const std::string &);

  private:
    Disassembly::Capstone m_capstone;
};
} // namespace Rev