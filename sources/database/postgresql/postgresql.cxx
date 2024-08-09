#include "postgresql.hxx"

namespace Database
{
    Postgresql::Postgresql(Parser::Toml &p_config) : m_config(p_config), m_conn("dbname=" + GET_TOML_TBL_VALUE(p_config, string, "database", "dbname") +
                                                                                "user=" + GET_TOML_TBL_VALUE(p_config, string, "database", "user") +
                                                                                "password=" + GET_TOML_TBL_VALUE(p_config, string, "database", "password") +
                                                                                "hostaddr=" + GET_TOML_TBL_VALUE(p_config, string, "database", "hostaddr") +
                                                                                "port=" + std::to_string(GET_TOML_TBL_VALUE(p_config, uint16_t, "database", "port")))
    {
    }

    Postgresql::Postgresql() : m_config(m_config), m_conn()
    {
    }

    Postgresql::~Postgresql()
    {
        if (m_conn.is_open())
            m_conn.close();
    }

    const void Postgresql::exec_query_commit(const std::string &p_sql) const
    {
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
            m_conn.close();
    }

}