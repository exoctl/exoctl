#pragma once

#include <engine/dto/dto.hxx>
#include <include/engine/disassembly/capstone/capstone.hxx>

namespace Rev
{
class CapstoneARM : public DTO::DTOBase
{
  public:
    CapstoneARM();
    ~CapstoneARM();

    void capstonearm_disassembly(const std::string &);

  private:
    Disassembly::Capstone m_capstone;
};
} // namespace Rev