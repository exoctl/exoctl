#include <engine/database/database.hxx>

namespace engine::database
{
    std::unique_ptr<soci::session> Database::session_;
    std::string Database::type;
    std::string Database::connection_str_;

    void Database::setup(const configuration::Configuration &config,
                         const logging::Logging &log)
    {
        config_ = config;
        log_ = log;

        type = config_.get("database.type")
                   .value<std::string>()
                   .value_or("sqlite");

        if (type == "sqlite") {
            std::string path =
                config_.get("database.path").value<std::string>().value();
            std::string file =
                config_.get("database.file").value<std::string>().value();
            connection_str_ = path + file;
            session_ = std::make_unique<soci::session>(soci::sqlite3,
                                                        connection_str_);
        } else if (type == "postgresql") {
            connection_str_ = config_.get("database.connection")
                                   .value<std::string>()
                                   .value();
            session_ = std::make_unique<soci::session>(soci::postgresql,
                                                        connection_str_);
        } else if (type == "mysql") {
            connection_str_ = config_.get("database.connection")
                                   .value<std::string>()
                                   .value();
            session_ =
                std::make_unique<soci::session>(soci::mysql, connection_str_);
        } else {
            throw exception::Initialize(
                fmt::format("Unsupported DB type '{}'", type));
        }

        log_.info(fmt::format("Connected to {} database successfully", type));
    }

    void Database::load()
    {
        load_schema();
        load_migrations();
    }

    void Database::load_schema()
    {
        std::string schema_path =
            config_.get("database.ddl.path").value<std::string>().value() +
            config_.get("database.ddl.schema").value<std::string>().value();
        load_sql_directory<exception::Schema>(schema_path);
    }

    void Database::load_migrations()
    {
        std::string migrations_path =
            config_.get("database.ddl.path").value<std::string>().value() +
            config_.get("database.ddl.migrations")
                .value<std::string>()
                .value();
        load_sql_directory<exception::Migrations>(migrations_path);
    }

    const bool Database::is_table_exists(const std::string &p_table)
    {
        bool exists = false;

        if (type == "sqlite") {
            int count = 0;
            (*session_)
                << "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND "
                   "name=:name",
                soci::use(p_table), soci::into(count);
            exists = (count > 0);
        } else if (type == "postgresql") {
            std::string result;
            std::string tblname = "public." + p_table;
            (*session_) << "SELECT to_regclass(:tblname)",
                soci::use(tblname, "tblname"), soci::into(result);
            exists = !result.empty();
        } else if (type == "mysql") {
            int count = 0;
            (*session_)
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
        return *session_;
    }

    void Database::close()
    {
        if (session_) {
            session_->close();
            session_.reset();
            log_.info("Database connection closed.");
        }
    }
} // namespace engine::database
