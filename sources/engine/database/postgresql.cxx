#include <engine/database/postgresql.hxx>

namespace Database
{
    Postgresql::Postgresql(Parser::Toml &p_config, Logging::Log &p_log)
        : m_config(p_config), m_log(p_log),
          m_conn(
              "dbname=" +
              GET_TOML_TBL_VALUE(p_config, string, "postgresql", "dbname") +
              "user=" +
              GET_TOML_TBL_VALUE(p_config, string, "postgresql", "user") +
              "password=" +
              GET_TOML_TBL_VALUE(p_config, string, "postgresql", "password") +
              "hostaddr=" +
              GET_TOML_TBL_VALUE(p_config, string, "postgresql", "hostaddr") +
              "port=" +
              std::to_string(
                  GET_TOML_TBL_VALUE(p_config, uint16_t, "postgresql", "port")))
    {
    }

    Postgresql::~Postgresql()
    {
        Postgresql::close_db();
    }

    void Postgresql::exec_query_commit(const std::string &p_sql) const
    {
        LOG(m_log,
            info,
            "Query commit '{:s}' executed in database '{:s}'",
            p_sql,
            m_conn.dbname());
        pqxx::work work(m_conn);
        work.exec(p_sql);
        work.commit();
    }

    void Postgresql::exec_query(
        const std::string &p_sql,
        const std::function<void(void *)> &p_callback) const
    {
        LOG(m_log,
            info,
            "Query '{:s}' executed in database '{:s}'",
            p_sql,
            m_conn.dbname());
        pqxx::nontransaction nontransaction(m_conn);
        pqxx::result result(nontransaction.exec(p_sql));
        p_callback((void *) &result);
    }

    const bool Postgresql::open_db() const
    {
        return m_conn.is_open();
    }

    const bool Postgresql::is_open_db() const
    {
        return m_conn.is_open();
    }

    void Postgresql::close_db() const
    {
        if (m_conn.is_open()) {
            LOG(m_log, info, "Database '{:s}' closed", m_conn.dbname());
#if (PQXX_VERSION_MAJOR < 7)
            m_conn.disconnect();
#else
            m_conn.close();
#endif
        }
    }

} // namespace Database