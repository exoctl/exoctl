#include "postgresql.hxx"

namespace Database
{
    Postgresql::Postgresql(Parser::Toml &p_config, Logging::Log &p_log) : m_config(p_config),
                                                                          m_log(p_log),
                                                                          m_conn("dbname=" + GET_TOML_TBL_VALUE(p_config, string, "database", "dbname") +
                                                                                 "user=" + GET_TOML_TBL_VALUE(p_config, string, "database", "user") +
                                                                                 "password=" + GET_TOML_TBL_VALUE(p_config, string, "database", "password") +
                                                                                 "hostaddr=" + GET_TOML_TBL_VALUE(p_config, string, "database", "hostaddr") +
                                                                                 "port=" + std::to_string(GET_TOML_TBL_VALUE(p_config, uint16_t, "database", "port")))
    {
    }

    Postgresql::Postgresql() : m_config(m_config), m_log(m_log), m_conn()
    {
    }

    Postgresql::~Postgresql()
    {
        Postgresql::close_db();
    }

    const void Postgresql::exec_query_commit(const std::string &p_sql) const
    {
        LOG(m_log, info, "Query commit '{:s}' executed in database '{:s}'", p_sql, m_conn.dbname());
        pqxx::work work(m_conn);
        work.exec(p_sql);
        work.commit();
    }

    const bool Postgresql::open_db() const
    {
        return m_conn.is_open();
    }

    const bool Postgresql::is_open_db() const
    {
        return m_conn.is_open();
    }

    const void Postgresql::close_db() const
    {
        if (m_conn.is_open())
        {
            LOG(m_log, info, "Database '{:s}' closed", m_conn.dbname());
            m_conn.close();
        }
    }

}