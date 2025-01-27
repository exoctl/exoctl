#pragma once

extern "C" {
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>
}
#include <atomic>
#include <engine/lua/exception.hxx>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <unordered_map>

namespace engine
{
    namespace lua
    {
        class Lua
        {
          public:
            Lua();
            ~Lua();

            bool load_script_file(const std::string &, const std::string &);

            void run();

            const bool call_function(const std::string &,
                                     const std::string &,
                                     int = 0,
                                     int = 0);

            template <typename T>
            static void register_global(const std::string &, T &);

            template <typename T>
            static void register_class(const std::string &name, T *obj)
            {
                luaL_newmetatable(m_state, name.c_str());
                lua_pushstring(m_state, "__index");
                lua_pushlightuserdata(m_state, obj);
                lua_settable(m_state, -3);

                lua_setglobal(m_state, name.c_str());
            }

            template <typename T>
            static void register_class_method(const std::string &,
                                              const std::string &,
                                              void (T::*)());

            template <typename T>
            static void register_class(const std::string &name,
                                       std::unique_ptr<T> &obj)
            {
                luaL_newmetatable(m_state, name.c_str());

                lua_pushstring(m_state, "__index");
                lua_pushlightuserdata(m_state, static_cast<void *>(obj.get()));
                lua_settable(m_state, -3);

                lua_pushstring(m_state, "__gc");
                lua_pushcfunction(m_state, [](lua_State *L) -> int {
                    std::unique_ptr<T> *obj_ptr =
                        static_cast<std::unique_ptr<T> *>(lua_touserdata(L, 1));
                    obj_ptr->reset();
                    return 0;
                });
                lua_settable(m_state, -3);

                lua_setglobal(m_state, name.c_str());
            }

            template <typename T>
            static void register_class_member(const std::string &class_name,
                                              const std::string &member_name,
                                              T &value)
            {
                luaL_getmetatable(m_state, class_name.c_str());
                if (lua_isnil(m_state, -1)) {
                    lua_pop(m_state, 1);
                    throw lua::exception::RegisterClassMember(
                        "Class not registered: " + class_name);
                }

                lua_pushstring(m_state, member_name.c_str());
                lua_pushlightuserdata(m_state, &value);

                lua_pushcclosure(
                    m_state,
                    [](lua_State *L) -> int {
                        T *ptr = static_cast<T *>(
                            lua_touserdata(L, lua_upvalueindex(1)));
                        if (lua_gettop(L) == 0) { // Getter
                            if constexpr (std::is_same_v<T, bool>) {
                                lua_pushboolean(L, *ptr);
                            } else if constexpr (std::is_same_v<T,
                                                                std::string>) {
                                lua_pushstring(L, ptr->c_str());
                            } else if constexpr (std::is_integral_v<T>) {
                                lua_pushinteger(L, *ptr);
                            } else {
                                lua_pushlightuserdata(L, ptr);
                            }
                        } else { // Setter
                            if constexpr (std::is_same_v<T, bool>) {
                                *ptr = lua_toboolean(L, 1);
                            } else if constexpr (std::is_same_v<T,
                                                                std::string>) {
                                *ptr = luaL_checkstring(L, 1);
                            } else if constexpr (std::is_integral_v<T>) {
                                *ptr = static_cast<T>(luaL_checkinteger(L, 1));
                            } else {
                                // Handle other types as needed
                            }
                        }
                        return 1;
                    },
                    1);
                lua_settable(m_state, -3);
                lua_pop(m_state, 1);
            }

            const std::unordered_map<std::string, std::string> &get_scripts();

          private:
            static lua_State *m_state;
            std::unordered_map<std::string, std::string> m_scripts;
            std::vector<std::thread> m_threads_scripts;

            Lua(const Lua &) = delete;
            Lua &operator=(const Lua &) = delete;
        };
    } // namespace lua
} // namespace engine
