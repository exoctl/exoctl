#include <engine/database/database.hxx>
#include <engine/database/exception.hxx>

namespace engine::database
{
    std::mutex Database::m_sql_queue_mutex;
    std::queue<record::EnqueueTask> Database::m_sql_queue;
    std::condition_variable Database::m_sql_queue_cv;
    std::atomic<bool> Database::is_running = true;
    std::atomic<int> Database::m_id_counter = 0;
    
    Database::Database() : m_database(nullptr), sql_queue_size(0)
    {
    }

    Database::~Database()
    {
        m_sql_queue_cv.notify_all();
        is_running = false;

        if (m_worker_thread.joinable()) {
            m_worker_thread.join();
        }
    
        Database::close();
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
        Database::load_sql_directory<exception::Schema>(
            m_config.get("database.ddl.path").value<std::string>().value() +
            m_config.get("database.ddl.schema").value<std::string>().value());
    }

    void Database::load_migrations()
    {
        Database::load_sql_directory<exception::Migrations>(
            m_config.get("database.ddl.path").value<std::string>().value() +
            m_config.get("database.ddl.migrations")
                .value<std::string>()
                .value());
    }

    void Database::enqueue_sql(record::EnqueueTask &p_task)
    {
        if (!is_running)
            return;

        p_task.id = ++m_id_counter;

        std::lock_guard<std::mutex> lock(m_sql_queue_mutex);
        m_sql_queue.push(p_task);
        m_sql_queue_cv.notify_one();
    }

    void Database::worker()
    {
        m_log.info("Database Worker thread started running.");
        while (is_running) {
            std::unique_lock<std::mutex> lock(m_sql_queue_mutex);
            m_sql_queue_cv.wait(
                lock, [this] { return !m_sql_queue.empty() || !is_running; });

            while (!m_sql_queue.empty()) {
                record::EnqueueTask task = m_sql_queue.front();
                m_sql_queue.pop();
                sql_queue_size = m_sql_queue.size();
                lock.unlock();

                m_log.info(
                    fmt::format("Executing Task ID {} from queue({})",
                                task.id,
                                sql_queue_size.load()));

                char *errmsg = nullptr;
                if (Database::exec_query(task.sql, nullptr, &errmsg) !=
                    SQLITE_OK) {
                    m_log.error(fmt::format(
                        "SQLite exec error on task {}: {}", task.id, errmsg));
                    sqlite3_free(errmsg);
                }

                lock.lock();
            }
        }
    }

    void Database::exec_query_commit(const std::string &sql)
    {
    }

    const int Database::exec_query(
        const std::string &p_sql,
        int (*p_callback)(void *, int, char **, char **),
        char **p_msg)
    {
        return sqlite3_exec(
            m_database, p_sql.c_str(), p_callback, p_msg, nullptr);
    }

    void Database::close() const
    {
        sqlite3_close_v2(m_database);
    }

} // namespace engine::database
