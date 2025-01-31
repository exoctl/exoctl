#pragma once

#include <string>

namespace engine::lua::record::plugin
{
    typedef enum Type {
        SCRIPT_FILE,
        SCRIPT_BUFF
    } Type;

    typedef struct Plugin {
        std::string script_path;
        std::string script;
        Type type;
    } Plugin;

} // namespace engine::lua::record::plugin
