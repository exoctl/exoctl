#pragma once

#include <capstone/capstone.h>
#include <stdint.h>

namespace engine
{
    namespace disassembly
    {
        namespace capstone
        {
            namespace record
            {
                typedef struct Data {
                    uint64_t address;
                    cs_insn *insn;
                } Data;
            } // namespace record
        } // namespace capstone
    } // namespace disassembly
} // namespace engine