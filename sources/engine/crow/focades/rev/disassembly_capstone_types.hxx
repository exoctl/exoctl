#pragma once

#include <include/engine/disassembly/capstone/capstone.hxx>
#include <map>
#include <string>

namespace Focades
{
    namespace Rev
    {
        namespace Structs
        {
            typedef struct DTO {
                std::string arch;
                std::string mode;
                std::map<std::string, std::string> instructions;
            } DTO;
        } // namespace Structs
    } // namespace Rev
} // namespace Focades