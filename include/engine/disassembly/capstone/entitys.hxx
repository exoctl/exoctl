#pragma once

#include <capstone/capstone.h>
#include <stdint.h>

namespace disassembly
{
    namespace capstone
    {
        namespace record
        {
            typedef struct Data {
                uint64_t capstone_address;
                cs_insn *capstone_insn;
            } Data;
        } // namespace structs
    } // namespace capstone
} // namespace disassembly