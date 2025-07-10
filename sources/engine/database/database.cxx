#include <engine/database/database.hxx>
#include <engine/database/exception.hxx>

namespace engine::database
{
    Database::Database()
        : is_running(true), m_database(nullptr),
          sql_queue_size(0)
    {
    }

    void Database::setup(const configuration::Configuration &p_config,
                         const logging::Logging &p_log)
    {
        m_log = p_log;
        m_config = p_config;
    }

    void Database::load()
    {
        std::string path =
            m_config.get("database.path").value<std::string>().value();
        std::string file =
            m_config.get("database.file").value<std::string>().value();
        int flags = m_config.get("database.flags").value<int>().value();
        std::string zvfs =
            m_config.get("database.zvfs").value<std::string>().value();

        m_log.info(fmt::format(
            "Opening Database at '{}{}' with flags {} and zvfs '{}'",
            path,
            file,
            flags,
            zvfs));

        if (sqlite3_open_v2(
                (path + file).c_str(), &m_database, flags, zvfs.c_str())) {
            m_log.error(fmt::format("Failed to open database: {}",
                                    sqlite3_errmsg(m_database)));
            throw exception::Initialize(sqlite3_errmsg(m_database));
        }

        m_log.info("Database connection opened successfully.");

        m_worker_thread = std::thread(&Database::worker, this);

        Database::load_schema();
        Database::load_migrations();
    }

    void Database::load_schema()
    {
        m_log.info("Loading schema...");
        // Descomente se quiser ativar o carregamento real
        // m_log.info(fmt::format("Loading schema from: {}/{}", schema_path,
        // schema_file));
    }

    void Database::load_migrations()
    {
        m_log.info("Loading migrations...");
        // m_log.info(fmt::format("Scanning migration directory: {}",
        // migration_path));
    }

    void Database::enqueue_sql(const std::string &sql)
    {
        m_log.info(fmt::format("Enqueueing SQL: {}",
                               sql.substr(0, 100))); 
        {
            std::lock_guard<std::mutex> lock(m_queue_mutex);
            m_sql_queue.push(sql);
        }
        m_queue_cv.notify_one();
    }

    void Database::worker()
    {
        m_log.info("Database Worker thread started running.");
        while (is_running) {
            std::unique_lock<std::mutex> lock(m_queue_mutex);
            m_queue_cv.wait(
                lock, [this] { return !m_sql_queue.empty() || !is_running; });

            while (!m_sql_queue.empty()) {
                const std::string sql = m_sql_queue.front();
                m_sql_queue.pop();
                sql_queue_size = m_sql_queue.size();
                lock.unlock();

                m_log.info(fmt::format("Executing SQL from queue: {}",
                                       sql.substr(0, 100)));

                char *errmsg = nullptr;
                if (sqlite3_exec(
                        m_database, sql.c_str(), nullptr, nullptr, &errmsg) !=
                    SQLITE_OK) {
                    m_log.error(fmt::format("SQLite exec error: {}", errmsg));
                    sqlite3_free(errmsg);
                }

                lock.lock();
            }
        }
    }

    void Database::exec_query_commit(const std::string &sql)
    {
        // m_log.info("Executing committed SQL query.");
        // char *errmsg = nullptr;
        // sqlite3_exec(m_database, "BEGIN;", nullptr, nullptr, nullptr);
        // if (sqlite3_exec(m_database, sql.c_str(), nullptr, nullptr, &errmsg)
        // !=
        //     SQLITE_OK) {
        //     m_log.error(fmt::format("SQL error: {}", errmsg));
        //     sqlite3_free(errmsg);
        // }
        // sqlite3_exec(m_database, "COMMIT;", nullptr, nullptr, nullptr);
    }

    const int Database::exec_query(
        const std::string &p_sql,
        const std::function<int(void *, int, char **, char **)> &p_callback)
    {
        m_log.info(fmt::format("Executing SQL query: {}", p_sql));
        return sqlite3_exec(
            m_database,
            p_sql.c_str(),
            *p_callback.target<int (*)(void *, int, char **, char **)>(),
            0,
            nullptr);
    }

    void Database::close() const
    {
        sqlite3_close_v2(m_database);
    }

    Database::~Database()
    {
        is_running = false;
        m_queue_cv.notify_all();
        if (m_worker_thread.joinable()) {
            m_worker_thread.join();
        }

        Database::close();
    }
} // namespace engine::database
