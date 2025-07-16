#include <engine/database/database.hxx>
#include <engine/database/extend/database.hxx>
#include <engine/plugins/exception.hxx>
#include <engine/plugins/plugins.hxx>

namespace engine::database::extend
{
    void Database::bind_database(engine::lua::StateView &p_lua)
    {
        p_lua.new_usertype<database::Database>(
            "Database",
            sol::constructors<database::Database()>(),
            "load",
            &database::Database::load,
            "setup",
            &database::Database::setup,
            "is_running",
            sol::property([](const database::Database &p_self) -> const bool {
                return p_self.is_running.load();
            }),
            "sql_queue_size",
            sol::property([](const database::Database &p_self) -> const size_t {
                return p_self.sql_queue_size.load();
            }));
    }

    void Database::_plugins()
    {
        Database::bind_database(plugins::Plugins::lua.state);
    }
} // namespace engine::database::extend