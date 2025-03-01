#pragma once

#include <string>

namespace engine::lua::record::script
{
    using Type = enum Type {
        SCRIPT_FILE,
        SCRIPT_BUFF
    };

    /*the important order*/
    using Plugin = struct Script {
        std::string path;
        std::string name;
        Type type;
    };
} // namespace engine::lua::record::script
