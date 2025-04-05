#pragma once

extern "C" {
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>
}
#include <any>
#include <atomic>
#include <engine/lua/entitys.hxx>
#include <engine/lua/exception.hxx>
#include <functional>
#include <memory>
#include <mutex>
#include <sol/sol.hpp>
#include <string>
#include <thread>
#include <tuple>
#include <type_traits>
#include <vector>
#include <memory>

namespace engine
{
    namespace lua
    {
        class Lua
        {
          public:
            Lua() = default;
            ~Lua() = default;
            sol::state state;
            std::shared_ptr<sol::environment> environment;

            [[nodiscard]] const sol::lib from_lib(const std::string &name);
            [[nodiscard]] const bool load_script_file(const std::string &,
                                                      const std::string &);
            [[nodiscard]] const bool load_script_buff(const std::string &);
            void run();

            std::vector<record::script::Script> scripts;

          private:
            Lua(const Lua &) = delete;
            Lua &operator=(const Lua &) = delete;
        };
    } // namespace lua
} // namespace engine