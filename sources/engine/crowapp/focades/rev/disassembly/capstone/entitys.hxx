#pragma once

#include <include/engine/disassembly/capstone/capstone.hxx>
#include <map>
#include <string>

namespace focades
{
    namespace rev
    {
        namespace disassembly
        {
            namespace capstone
            {
                namespace record
                {
                    typedef struct Instruction {
                        std::string capstone_address;
                        std::string capstone_mnemonic;
                        std::string capstone_operands;
                        uint16_t capstone_size;
                        int capstone_id;
                        std::string capstone_bytes;
                    } Instruction;

                    typedef struct DTO {
                        std::string capstone_arch;
                        std::string capstone_mode;
                        std::vector<Instruction> capstone_instructions;
                    } DTO;
                } // namespace record
            } // namespace capstone
        } // namespace disassembly
    } // namespace rev
} // namespace focades