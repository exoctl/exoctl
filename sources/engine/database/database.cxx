#include <engine/database/database.hxx>

namespace engine::database
{
    std::unique_ptr<soci::session> Database::m_session;
    std::string Database::type;
    std::string Database::m_connection_str;

    void Database::setup(const configuration::Configuration &config,
                         const logging::Logging &log)
    {
        m_config = config;
        m_log = log;

        type = m_config.get("database.type")
                   .value<std::string>()
                   .value_or("sqlite");

        if (type == "sqlite") {
            std::string path =
                m_config.get("database.path").value<std::string>().value();
            std::string file =
                m_config.get("database.file").value<std::string>().value();
            m_connection_str = path + file;
            m_session = std::make_unique<soci::session>(soci::sqlite3,
                                                        m_connection_str);
        } else if (type == "postgresql") {
            m_connection_str = m_config.get("database.connection")
                                   .value<std::string>()
                                   .value();
            m_session = std::make_unique<soci::session>(soci::postgresql,
                                                        m_connection_str);
        } else if (type == "mysql") {
            m_connection_str = m_config.get("database.connection")
                                   .value<std::string>()
                                   .value();
            m_session =
                std::make_unique<soci::session>(soci::mysql, m_connection_str);
        } else {
            throw exception::Initialize(
                fmt::format("Unsupported DB type '{}'", type));
        }

        m_log.info(fmt::format("Connected to {} database successfully", type));
    }

    void Database::load()
    {
        load_schema();
        load_migrations();
    }

    void Database::load_schema()
    {
        std::string schema_path =
            m_config.get("database.ddl.path").value<std::string>().value() +
            m_config.get("database.ddl.schema").value<std::string>().value();
        load_sql_directory<exception::Schema>(schema_path);
    }

    void Database::load_migrations()
    {
        std::string migrations_path =
            m_config.get("database.ddl.path").value<std::string>().value() +
            m_config.get("database.ddl.migrations")
                .value<std::string>()
                .value();
        load_sql_directory<exception::Migrations>(migrations_path);
    }

    const bool Database::is_table_exists(const std::string &p_table)
    {
        bool exists = false;

        if (type == "sqlite") {
            int count = 0;
            (*m_session)
                << "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND "
                   "name=:name",
                soci::use(p_table), soci::into(count);
            exists = (count > 0);
        } else if (type == "postgresql") {
            std::string result;
            std::string tblname = "public." + p_table;
            (*m_session) << "SELECT to_regclass(:tblname)",
                soci::use(tblname, "tblname"), soci::into(result);
            exists = !result.empty();
        } else if (type == "mysql") {
            int count = 0;
            (*m_session)
                << "SELECT COUNT(*) FROM information_schema.tables "
                   "WHERE table_schema = DATABASE() AND table_name = :name",
                soci::use(p_table), soci::into(count);
            exists = (count > 0);
        } else {
            return exists;
        }

        return exists;
    }

    Soci &Database::exec()
    {
        return *m_session;
    }

    void Database::close()
    {
        if (m_session) {
            m_session->close();
            m_session.reset();
            m_log.info("Database connection closed.");
        }
    }
} // namespace engine::database
