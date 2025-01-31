#pragma once

#include <application/anti/debug/scripts/gdb.hxx>
#include <engine/lua/lua.hxx>

namespace application::anti::debug
{
    class Debug
    {
      public:
        Debug();
        ~Debug() = default;

        void run();

      private:
        engine::lua::Lua m_lua;
        void run_plugins_thread();
    };
} // namespace application::anti::debug