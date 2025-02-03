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
        const std::vector<record::plugin::Plugin> &Lua::get_scripts()
        {
            return m_scripts;
        }

        bool Lua::load_script_buff(const std::string &p_buff)
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

            m_scripts.push_back(
                {m_script_name, p_buff, record::plugin::SCRIPT_BUFF});
            return true;
        }

        bool Lua::load_script_file(const std::string &p_script_name,
                                   const std::string &p_script_path)
        {

            if (!state.load_file(p_script_path.c_str()).valid()) {
                return false;
            }

            m_scripts.push_back(
                {p_script_name, p_script_path, record::plugin::SCRIPT_FILE});
            return true;
        }

        void Lua::run()
        {
            for (const auto &plugin : m_scripts) {
                TRY_BEGIN()
                if (plugin.type == record::plugin::SCRIPT_FILE) {
                    state.safe_script_file(plugin.script,
                                           sol::script_pass_on_error);
                } else if (plugin.type == record::plugin::SCRIPT_BUFF) {
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
