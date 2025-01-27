#include <engine/lua/exception.hxx>
#include <engine/lua/lua.hxx>
#include <mutex>
#include <string>
#include <thread>
#include <type_traits>
#include <unordered_map>
#include <vector>

namespace engine
{
    namespace lua
    {
        lua_State *Lua::m_state = nullptr;
        std::mutex Lua::m_state_mutex;
        std::vector<lua_State *> Lua::m_threads;

        Lua::Lua()
        {
            std::lock_guard<std::mutex> lock(m_state_mutex);
            if (!m_state) {
                m_state = luaL_newstate();
                luaL_openlibs(m_state);
            }
        }

        Lua::~Lua()
        {
            for (auto &t : m_threads_scripts) {
                if (t.joinable()) {
                    t.join();
                }
            }

            std::lock_guard<std::mutex> lock(m_state_mutex);
            if (m_state) {
                for (const auto &_ : m_threads) {
                    luaL_unref(m_state,
                               LUA_REGISTRYINDEX,
                               luaL_ref(m_state, LUA_REGISTRYINDEX));
                }
                m_threads.clear();

                lua_close(m_state);
                m_state = nullptr;
            }
        }

        const std::unordered_map<std::string, std::string> &Lua::get_scripts()
        {
            return m_scripts;
        }

        bool Lua::load_script_file(const std::string &p_script_name,
                                   const std::string &p_script_path)
        {
            std::lock_guard<std::mutex> lock(m_state_mutex);
            if (m_scripts.find(p_script_name) != m_scripts.end()) {
                return false;
            }

            if (luaL_loadfile(m_state, p_script_path.c_str()) != LUA_OK) {
                lua_pop(m_state, 1);
                return false;
            }

            m_scripts[p_script_name] = p_script_path;
            return true;
        }

        const bool Lua::call_function(const std::string &p_function_name,
                                      int p_arg_count,
                                      int p_ret_count)
        {
            lua_getglobal(m_state, p_function_name.c_str());
            if (!lua_isfunction(m_state, -1)) {
                lua_pop(m_state, 1);
                return false;
            }

            if (lua_pcall(m_state, p_arg_count, p_ret_count, 0) != LUA_OK) {
                lua_pop(m_state, 1);
                return false;
            }

            return true;
        }

        void Lua::run()
        {
            m_threads_scripts.reserve(m_scripts.size());

            for (const auto &[script_name, script_path] : m_scripts) {
                m_threads_scripts.push_back(std::thread([this, script_path]() {
                    lua_State *L_thread = lua_newthread(m_state);

                    lua_pushthread(L_thread);
                    int ref = luaL_ref(m_state, LUA_REGISTRYINDEX);
                    m_threads.push_back(L_thread);

                    if (luaL_dofile(L_thread, script_path.c_str()) != LUA_OK) {
                        lua_pop(L_thread, 1);
                    }

                    luaL_unref(m_state, LUA_REGISTRYINDEX, ref);
                }));
            }
        }

        template <>
        void Lua::register_global<int>(const std::string &name, int &value)
        {
            std::lock_guard<std::mutex> lock(m_state_mutex);
            lua_pushlightuserdata(m_state, &value);
            lua_pushcclosure(
                m_state,
                [](lua_State *L) -> int {
                    int *ptr = static_cast<int *>(
                        lua_touserdata(L, lua_upvalueindex(1)));
                    if (lua_gettop(L) == 0) {
                        lua_pushinteger(L, *ptr);
                    } else {
                        *ptr = lua_tointeger(L, 1);
                    }
                    return 1;
                },
                1);
            lua_setglobal(m_state, name.c_str());
        }

        template <>
        void Lua::register_global<bool>(const std::string &name, bool &value)
        {
            std::lock_guard<std::mutex> lock(m_state_mutex);
            lua_pushlightuserdata(m_state, &value);
            lua_pushcclosure(
                m_state,
                [](lua_State *L) -> int {
                    bool *ptr = static_cast<bool *>(
                        lua_touserdata(L, lua_upvalueindex(1)));
                    if (lua_gettop(L) == 0) {
                        lua_pushboolean(L, *ptr);
                    } else {
                        *ptr = lua_toboolean(L, 1);
                    }
                    return 1;
                },
                1);
            lua_setglobal(m_state, name.c_str());
        }

        template <>
        void Lua::register_global<std::string>(const std::string &name,
                                               std::string &value)
        {
            std::lock_guard<std::mutex> lock(m_state_mutex);
            lua_pushlightuserdata(m_state, &value);
            lua_pushcclosure(
                m_state,
                [](lua_State *L) -> int {
                    std::string *ptr = static_cast<std::string *>(
                        lua_touserdata(L, lua_upvalueindex(1)));
                    if (lua_gettop(L) == 0) {
                        lua_pushstring(L, ptr->c_str());
                    } else {
                        *ptr = lua_tostring(L, 1);
                    }
                    return 1;
                },
                1);
            lua_setglobal(m_state, name.c_str());
        }

        template <typename T>
        void Lua::register_class_method(const std::string &class_name,
                                        const std::string &method_name,
                                        void (T::*method)())
        {
            std::lock_guard<std::mutex> lock(m_state_mutex);
            lua_getglobal(m_state, class_name.c_str());
            lua_pushstring(m_state, method_name.c_str());
            lua_pushlightuserdata(m_state, method);

            lua_pushcfunction(m_state, [](lua_State *L) -> int {
                T *obj = static_cast<T *>(lua_touserdata(L, 1));
                auto method = reinterpret_cast<void (T::*)()>(
                    lua_touserdata(L, lua_upvalueindex(1)));
                (obj->*method)();
                return 0;
            });

            lua_settable(m_state, -3);
        }

    } // namespace lua
} // namespace engine