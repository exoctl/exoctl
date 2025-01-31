#include <application/anti/debug/debug.hxx>
#include <engine/lua/lua.hxx>
#include <iostream>
#include <thread>

namespace application::anti::debug
{
    Debug::Debug() : m_lua()
    {
        m_lua.load_script_buff(ANTI_DEBUG_PTRACE);
        m_lua.load_script_buff(ANTI_DEBUG_BREAKPOINTS);
        m_lua.load_script_buff(ANTI_DEBUG_HOOK);
    }

    void Debug::run()
    {
        std::thread(&Debug::run_plugins_thread, this).detach();
    }

    void Debug::run_plugins_thread()
    {
        m_lua.run();
    }
} // namespace application::anti::debug
