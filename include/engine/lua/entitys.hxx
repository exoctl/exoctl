#pragma once

#include <string>

namespace engine::lua::record
{
    namespace script
    {
        typedef enum Type {
            SCRIPT_FILE,
            SCRIPT_BUFF
        } Type;

        typedef struct Script {
            std::string script_path;
            std::string script;
            Type type;
        } Plugin;
    } // namespace script
    
} // namespace engine::lua::record
