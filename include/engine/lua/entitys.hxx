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

        /*the important order*/
        typedef struct Script {
            std::string path;
            std::string name;
            Type type;
        } Plugin;
    } // namespace script

} // namespace engine::lua::record
