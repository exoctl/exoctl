#pragma once

namespace Disassembly
{
    namespace Struct
    {
        typedef struct Data {
            uint64_t address;
            cs_insn *insn;
        } Data;
    } // namespace Struct
} // namespace Disassembly