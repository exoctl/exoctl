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
            ~Lua();

            bool load_script_file(const std::string &, const std::string &);
            bool load_script_buff(const std::string &);

            void run();

            const bool call_function(const std::string &, int = 0, int = 0);

            template <typename T>
            static void register_global(const std::string &, T &);

            template <typename T>
            static void register_class(const std::string &name, T *obj)
            {
                std::lock_guard<std::mutex> lock(m_state_mutex);

                luaL_newmetatable(m_state, name.c_str());
                lua_pushstring(m_state, "__index");
                lua_pushlightuserdata(m_state, obj);
                lua_settable(m_state, -3);

                lua_setglobal(m_state, name.c_str());
            }

            template <typename... Args>
            static void register_class_method(
                const std::string &class_name,
                const std::string &method_name,
                std::function<std::any(Args...)> method)
            {
                luaL_getmetatable(m_state, class_name.c_str());
                if (lua_isnil(m_state, -1)) {
                    lua_pop(m_state, 1);
                    throw exception::RegisterClassMethod(
                        "Class not registered: " + class_name);
                }

                lua_pushstring(m_state, method_name.c_str());
                lua_pushlightuserdata(
                    m_state, new std::function<std::any(Args...)>(method));

                lua_pushcclosure(
                    m_state,
                    [](lua_State *L) -> int {
                        auto method =
                            static_cast<std::function<std::any(Args...)> *>(
                                lua_touserdata(L, lua_upvalueindex(1)));

                        std::tuple<Args...> args;

                        if (lua_gettop(L) < static_cast<int>(sizeof...(Args))) {
                            // Handle error: not enough arguments
                            luaL_error(L, "Not enough arguments");
                        }

                        int index = 1;
                        auto extract_arg = [&](auto &arg) {
                            using T = std::decay_t<decltype(arg)>;
                            if constexpr (std::is_same_v<T, int>) {
                                arg = static_cast<T>(lua_tointeger(L, index));
                            } else if constexpr (std::is_same_v<T, double>) {
                                arg = static_cast<T>(lua_tonumber(L, index));
                            } else if constexpr (std::is_same_v<T,
                                                                std::string>) {
                                const char *str = lua_tostring(L, index);
                                arg = (str ? std::string(str) : "");
                            } else if constexpr (std::is_pointer_v<T>) {
                                arg = static_cast<T>(lua_touserdata(L, index));
                            } else {
                                static_assert(sizeof(T) == 0,
                                              "Unsupported argument type");
                            }
                            index++;
                        };

                        std::apply(
                            [&](auto &...args) { (extract_arg(args), ...); },
                            args);

                        std::any result = std::apply(*method, args);

                        if (result.has_value()) {
                            if (result.type() == typeid(int)) {
                                lua_pushinteger(L, std::any_cast<int>(result));
                            } else if (result.type() == typeid(double)) {
                                lua_pushnumber(L,
                                               std::any_cast<double>(result));
                            } else if (result.type() == typeid(std::string)) {
                                lua_pushstring(
                                    L,
                                    std::any_cast<std::string>(result).c_str());
                            } else if (result.type() == typeid(const char *)) {
                                lua_pushstring(
                                    L, std::any_cast<const char *>(result));
                            } else if (result.type() == typeid(void *)) {
                                lua_pushlightuserdata(
                                    L, std::any_cast<void *>(result));
                            } else {
                                throw exception::RegisterClassMethod(
                                    "Unsupported return type");
                            }
                        } else {
                            lua_pushnil(L);
                        }

                        return 1;
                    },
                    1);

                lua_settable(m_state, -3);
                lua_pop(m_state, 1);
            }

            template <typename T>
            static void register_class(const std::string &name,
                                       std::unique_ptr<T> &obj)
            {
                std::lock_guard<std::mutex> lock(m_state_mutex);

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
                std::lock_guard<std::mutex> lock(m_state_mutex);

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

            const std::vector<record::plugin::Plugin> &get_scripts();

          private:
            static std::mutex m_state_mutex;
            static lua_State *m_state;
            static std::vector<lua_State *> m_threads;

            std::vector<record::plugin::Plugin> m_scripts;
            std::vector<std::thread> m_threads_scripts;

            Lua(const Lua &) = delete;
            Lua &operator=(const Lua &) = delete;
        };
    } // namespace lua
} // namespace engine