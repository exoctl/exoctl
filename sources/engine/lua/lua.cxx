#include <engine/lua/exception.hxx>
#include <engine/lua/lua.hxx>
#include <fmt/core.h>
#include <fstream>
#include <random>
#include <string>
#include <thread>
#include <type_traits>
#include <vector>

namespace engine
{
    namespace lua
    {

        // state.open_libraries(sol::lib::base,
        //                      sol::lib::package,
        //                      sol::lib::coroutine,
        //                      sol::lib::string,
        //                      sol::lib::os,
        //                      sol::lib::math,
        //                      sol::lib::table,
        //                      sol::lib::debug,
        //                      sol::lib::bit32,
        //                      sol::lib::io,
        //                      sol::lib::ffi,
        //                      sol::lib::jit);

        const bool Lua::load_script_buff(const std::string &p_buff)
        {
            auto generate_random_name = []() {
                std::random_device rd;
                std::mt19937 gen(rd());
                std::uniform_int_distribution<> dis(0, 25);

                std::string random_name;
                for (int i = 0; i < 8; ++i) {
                    random_name += fmt::format("{}", char('a' + dis(gen)));
                }
                return random_name;
            };

            const std::string m_script_name = generate_random_name();

            if (!state.load(p_buff.c_str()).valid()) {
                return false;
            }

            scripts.push_back(
                {m_script_name, p_buff, record::script::SCRIPT_BUFF});
            return true;
        }

        const sol::lib Lua::from_lib(const std::string &name)
        {
            static const std::unordered_map<std::string, sol::lib> lib_map = {
                {"base", sol::lib::base},
                {"package", sol::lib::package},
                {"coroutine", sol::lib::coroutine},
                {"string", sol::lib::string},
                {"os", sol::lib::os},
                {"math", sol::lib::math},
                {"table",sol::lib::table},
                {"debug",sol::lib::debug},
                {"bit32",sol::lib::bit32},
                {"io", sol::lib::io},
                {"ffi", sol::lib::ffi},
                {"jit", sol::lib::jit},
                {"utf8", sol::lib::utf8}};

            auto it = lib_map.find(name);
            return (it != lib_map.end()) ? it->second : sol::lib::count;
        }

        const bool Lua::load_script_file(const std::string &p_script_name,
                                         const std::string &p_script_path)
        {

            if (!state.load_file(p_script_path.c_str()).valid()) {
                return false;
            }

            scripts.push_back(
                {p_script_name, p_script_path, record::script::SCRIPT_FILE});
            return true;
        }

        void Lua::run()
        {
            for (const auto &plugin : scripts) {
                TRY_BEGIN()
                if (plugin.type == record::script::SCRIPT_FILE) {
                    state.safe_script_file(plugin.script,
                                           sol::script_pass_on_error);
                } else if (plugin.type == record::script::SCRIPT_BUFF) {
                    state.safe_script(plugin.script, sol::script_pass_on_error);
                } else {
                    state.safe_script(plugin.script, sol::script_pass_on_error);
                }
                TRY_END()
                CATCH(sol::error, { throw exception::Run(e.what()); })
            }
        }

    } // namespace lua
} // namespace engine
