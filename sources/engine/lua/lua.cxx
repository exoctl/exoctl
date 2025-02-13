#include <algorithm>
#include <array>
#include <engine/lua/exception.hxx>
#include <engine/lua/lua.hxx>
#include <fmt/core.h>
#include <fstream>
#include <random>
#include <string>
#include <string_view>
#include <thread>

namespace engine::lua
{
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

        scripts.push_back({m_script_name, p_buff, record::script::SCRIPT_BUFF});
        return true;
    }

    const sol::lib Lua::from_lib(const std::string &name)
    {
        using Pair = std::pair<std::string_view, sol::lib>;

        static constexpr std::array<Pair, 13> lib_array = {
            {{"base", sol::lib::base},
             {"bit32", sol::lib::bit32},
             {"coroutine", sol::lib::coroutine},
             {"debug", sol::lib::debug},
             {"ffi", sol::lib::ffi},
             {"io", sol::lib::io},
             {"jit", sol::lib::jit},
             {"math", sol::lib::math},
             {"os", sol::lib::os},
             {"package", sol::lib::package},
             {"string", sol::lib::string},
             {"table", sol::lib::table},
             {"utf8", sol::lib::utf8}}};

        auto it =
            std::lower_bound(lib_array.begin(),
                             lib_array.end(),
                             name,
                             [](const Pair &pair, const std::string_view key) {
                                 return pair.first < key;
                             });

        return (it != lib_array.end() && it->first == name) ? it->second
                                                            : sol::lib::count;
    }

    const bool Lua::load_script_file(const std::string &p_script_name,
                                     const std::string &p_script_path)
    {

        if (!state.load_file(p_script_path.c_str()).valid()) {
            return false;
        }

        scripts.push_back(
            {p_script_path, p_script_name, record::script::SCRIPT_FILE});
        return true;
    }

    void Lua::run()
    {
        for (const auto &plugin : scripts) {
            TRY_BEGIN()
            if (plugin.type == record::script::SCRIPT_FILE) {
                state.safe_script_file(plugin.path, sol::script_pass_on_error);
            } else if (plugin.type == record::script::SCRIPT_BUFF) {
                state.safe_script(plugin.path, sol::script_pass_on_error);
            } else {
                state.safe_script(plugin.path, sol::script_pass_on_error);
            }
            TRY_END()
            CATCH(sol::error, { throw exception::Run(e.what()); })
        }
    }

} // namespace engine::lua
