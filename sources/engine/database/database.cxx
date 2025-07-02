#include <engine/database/database.hxx>
#include <engine/database/exception.hxx>

namespace engine::database
{
    void Database::setup(const configuration::Configuration &p_config)
    {
        m_config = p_config;
    }

    void Database::load()
    {
        if (sqlite3_open_v2(
                m_config.get("database.name").value<std::string>().value().data(),
                &m_database,
                m_config.get("database.flags").value<int>().value(),
                m_config.get("database.zvfs").value<std::string>().value().data())) {
            throw exception::Initialize(sqlite3_errmsg(m_database));
        }
    }

    const bool Database::is_db_open() const
    {
        return true;
    }

    void Database::exec_db_query_commit(const std::string &)
    {
    }

    const int Database::exec_db_query(
        const std::string &p_sql,
        const std::function<int(void *, int, char **, char **)> &p_callback)
    {
        return sqlite3_exec(
            m_database,
            p_sql.c_str(),
            *p_callback.target<int (*)(void *, int, char **, char **)>(),
            0,
            nullptr);
    }

    void Database::close_db() const
    {
        sqlite3_close_v2(m_database);
    }

    Database::~Database()
    {
        Database::close_db();
    }
} // namespace engine::database