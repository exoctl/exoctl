#include <engine/lua/exception.hxx>
#include <engine/lua/lua.hxx>
#include <string>
#include <type_traits>
#include <unordered_map>

namespace engine
{
    namespace lua
    {
        lua_State *Lua::m_state = nullptr;

        Lua::Lua()
        {
            if (!m_state) {
                m_state = luaL_newstate();
                luaL_openlibs(m_state);
            }
        }

        Lua::~Lua()
        {
            if (m_state) {
                lua_close(m_state);
            }
        }

        const std::unordered_map<std::string, std::string> &Lua::get_scripts()
        {
            return m_scripts;
        }

        bool Lua::load_script_file(const std::string &p_script_name,
                                   const std::string &p_script_path)
        {
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

        const bool Lua::call_function(const std::string &p_script_name,
                                      const std::string &p_function_name,
                                      int p_arg_count,
                                      int p_ret_count)
        {
            if (m_scripts.find(p_script_name) == m_scripts.end()) {
                return false;
            }

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
            for (const auto &[script_name, script_path] : m_scripts) {
                if (luaL_dofile(m_state, script_path.c_str()) != LUA_OK) {
                    lua_pop(m_state, 1);
                }
            }
        }

        template <>
        void Lua::register_global<int>(const std::string &name, int &value)
        {
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

        template <typename T>
        void Lua::register_class_member(const std::string &class_name,
                                        const std::string &member_name,
                                        T &member)
        {
            static_assert(sizeof(T) == 0,
                          "Unsupported type for register_class_member.");
        }

        template <>
        void Lua::register_class_member<unsigned short>(
            const std::string &class_name,
            const std::string &member_name,
            unsigned short &member)
        {
            luaL_getmetatable(m_state, class_name.c_str());
            if (lua_isnil(m_state, -1)) {
                lua_pop(m_state, 1);
                throw lua::exception::RegisterClassMember(
                    "Class not registered: " + class_name);
            }

            lua_pushstring(m_state, member_name.c_str());
            lua_pushlightuserdata(m_state, &member);
            lua_pushcclosure(
                m_state,
                [](lua_State *L) -> int {
                    unsigned short *ptr = static_cast<unsigned short *>(
                        lua_touserdata(L, lua_upvalueindex(1)));
                    if (lua_gettop(L) == 0) { // Getter
                        lua_pushinteger(L, *ptr);
                    } else { // Setter
                        *ptr = luaL_checkinteger(L, 1);
                    }
                    return 1;
                },
                1);
            lua_settable(m_state, -3);
            lua_pop(m_state, 1);
        }

        template <>
        void Lua::register_class_member<int>(const std::string &class_name,
                                             const std::string &member_name,
                                             int &member)
        {
            luaL_getmetatable(m_state, class_name.c_str());
            if (lua_isnil(m_state, -1)) {
                lua_pop(m_state, 1);
                throw lua::exception::RegisterClassMember(
                    "Class not registered: " + class_name);
            }

            lua_pushstring(m_state, member_name.c_str());
            lua_pushlightuserdata(m_state, &member);
            lua_pushcclosure(
                m_state,
                [](lua_State *L) -> int {
                    int *ptr = static_cast<int *>(
                        lua_touserdata(L, lua_upvalueindex(1)));
                    if (lua_gettop(L) == 0) { // Getter
                        lua_pushinteger(L, *ptr);
                    } else { // Setter
                        *ptr = luaL_checkinteger(L, 1);
                    }
                    return 1;
                },
                1);
            lua_settable(m_state, -3);
            lua_pop(m_state, 1);
        }

        template <>
        void Lua::register_class_member<std::string>(
            const std::string &class_name,
            const std::string &member_name,
            std::string &member)
        {
            luaL_getmetatable(m_state, class_name.c_str());
            if (lua_isnil(m_state, -1)) {
                lua_pop(m_state, 1);
                throw lua::exception::RegisterClassMember(
                    "Class not registered: " + class_name);
            }

            lua_pushstring(m_state, member_name.c_str());
            lua_pushlightuserdata(m_state, &member);
            lua_pushcclosure(
                m_state,
                [](lua_State *L) -> int {
                    std::string *ptr = static_cast<std::string *>(
                        lua_touserdata(L, lua_upvalueindex(1)));
                    if (lua_gettop(L) == 0) { // Getter
                        lua_pushstring(L, ptr->c_str());
                    } else { // Setter
                        *ptr = luaL_checkstring(L, 1);
                    }
                    return 1;
                },
                1);
            lua_settable(m_state, -3);
            lua_pop(m_state, 1);
        }

        // Especialização para `bool`
        template <>
        void Lua::register_class_member<bool>(const std::string &class_name,
                                              const std::string &member_name,
                                              bool &member)
        {
            luaL_getmetatable(m_state, class_name.c_str());
            if (lua_isnil(m_state, -1)) {
                lua_pop(m_state, 1);
                throw std::runtime_error("Class not registered: " + class_name);
            }

            lua_pushstring(m_state, member_name.c_str());
            lua_pushlightuserdata(m_state, &member);
            lua_pushcclosure(
                m_state,
                [](lua_State *L) -> int {
                    bool *ptr = static_cast<bool *>(
                        lua_touserdata(L, lua_upvalueindex(1)));
                    if (lua_gettop(L) == 0) { // Getter
                        lua_pushboolean(L, *ptr);
                    } else { // Setter
                        *ptr = lua_toboolean(L, 1);
                    }
                    return 1;
                },
                1);
            lua_settable(m_state, -3);
            lua_pop(m_state, 1);
        }

        template <>
        void Lua::register_class_member<double>(const std::string &class_name,
                                                const std::string &member_name,
                                                double &member)
        {
            luaL_getmetatable(m_state, class_name.c_str());
            if (lua_isnil(m_state, -1)) {
                lua_pop(m_state, 1);
                throw lua::exception::RegisterClassMember(
                    "Class not registered: " + class_name);
            }

            lua_pushstring(m_state, member_name.c_str());
            lua_pushlightuserdata(m_state, &member);
            lua_pushcclosure(
                m_state,
                [](lua_State *L) -> int {
                    double *ptr = static_cast<double *>(
                        lua_touserdata(L, lua_upvalueindex(1)));
                    if (lua_gettop(L) == 0) { // Getter
                        lua_pushnumber(L, *ptr);
                    } else { // Setter
                        *ptr = luaL_checknumber(L, 1);
                    }
                    return 1;
                },
                1);
            lua_settable(m_state, -3);
            lua_pop(m_state, 1);
        }

        lua_State *Lua::get_state() const
        {
            return m_state;
        }
    } // namespace lua
} // namespace engine
