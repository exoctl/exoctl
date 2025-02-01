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
#include <unordered_map>
#include <vector>

namespace engine
{
    namespace lua
    {
        class Lua
        {
          public:
            Lua();
            ~Lua() = default;

            bool load_script_file(const std::string &, const std::string &);
            bool load_script_buff(const std::string &);
            void run();
            const std::vector<record::plugin::Plugin> &get_scripts();
            sol::state lua;

          private:

            std::vector<record::plugin::Plugin> m_scripts;

            Lua(const Lua &) = delete;
            Lua &operator=(const Lua &) = delete;
        };
    } // namespace lua
} // namespace engine