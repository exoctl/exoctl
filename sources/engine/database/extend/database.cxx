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
            "exec",
            &database::Database::exec);
    }

    void Database::_plugins()
    {
        Database::bind_database(plugins::Plugins::lua.state);
    }
} // namespace engine::database::extend