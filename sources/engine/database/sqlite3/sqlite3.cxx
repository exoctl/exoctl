#include <engine/database/sqlite3/exception.hxx>
#include <engine/database/sqlite3/sqlite3.hxx>

namespace engine::database::sqlite3
{
    void Sqlite3::setup(const std::string &p_path,
                        const int p_flags,
                        const char *p_zvfs)
    {
        if (sqlite3_open_v2(p_path.c_str(), &m_database, p_flags, p_zvfs)) {
            throw exception::Initialize(sqlite3_errmsg(m_database));
        }
    }

    const bool Sqlite3::is_db_open() const
    {
        return true;
    }

    void Sqlite3::exec_db_query_commit(const std::string &)
    {
    }

    const int Sqlite3::exec_db_query(
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

    void Sqlite3::close_db() const
    {
        sqlite3_close_v2(m_database);
    }

    Sqlite3::~Sqlite3()
    {
        Sqlite3::close_db();
    }
} // namespace engine::database::sqlite3