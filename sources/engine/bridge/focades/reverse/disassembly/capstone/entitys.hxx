#pragma once

#include <include/engine/disassembly/capstone/capstone.hxx>
#include <map>
#include <string>

namespace engine::bridge::focades::reverse::disassembly
{
    namespace capstone
    {
        namespace record
        {
            typedef struct Instruction {
                std::string address;
                std::string mnemonic;
                std::string operands;
                uint16_t size;
                int id;
                std::string bytes;
            } Instruction;

            typedef struct DTO {
                std::string arch;
                std::string mode;
                std::vector<Instruction> instructions;
            } DTO;
        } // namespace record
    } // namespace capstone
} // namespace engine::bridge::focades::reverse::disassembly
