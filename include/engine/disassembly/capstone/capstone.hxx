#pragma once

#include <capstone/capstone.h>
#include <functional>

namespace Disassembly
{
struct cs_user_data
{
    uint64_t address;
    cs_insn *insn;
};

class Capstone
{
  public:
    Capstone(cs_arch, cs_mode);
    ~Capstone();

    void capstone_disassembly(const uint8_t *,
                     size_t,
                     const std::function<void(cs_user_data *, size_t)> &);

    const cs_arch capstone_get_arch();
    const cs_mode capstone_get_mode();

  private:
    csh m_handle;
    const cs_arch m_arch;
    const cs_mode m_mode;
};
} // namespace Disassembly