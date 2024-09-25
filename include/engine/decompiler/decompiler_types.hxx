#pragma once

#include <engine/disassembly/capstone/capstone_types.hxx>
#include <stdint.h>

namespace Decompiler
{
    namespace Structs
    {
        typedef struct Function {
            uint64_t start_function, end_function;
        } Function;

        typedef struct JumpBlock {
            unsigned int flags;
            uint64_t jump_start, jump_end;
            Disassembly::Struct::Data *instructions;
            int num_instructions;
            size_t instructions_buf_size;
            unsigned int *conditional_jumps; // Target addresses of all
                                             // conditional jumps in block
            int num_conditional_jumps;
            size_t conditional_jumps_buf_size;
            unsigned int
                *calls; // Target addresses of all additional calls in block
            int num_calls;
            size_t calls_buf_size;
            struct JumpBlock *next;
        } JumpBlock;
    } // namespace Structs

} // namespace Decompiler