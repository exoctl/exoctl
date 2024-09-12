#pragma once

#include <engine/dto/dto.hxx>
#include <include/engine/disassembly/capstone/capstone.hxx>

namespace Rev
{
class CapstoneARM64 : public DTO::DTOBase
{
  public:
    CapstoneARM64();
    ~CapstoneARM64();

    void capstonearm64_disassembly(const std::string &);

  private:
    Disassembly::Capstone m_capstone;
};
} // namespace Rev