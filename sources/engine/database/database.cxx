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
                std::string(
                    m_config.get("database.filepath")
                        .value<std::string>()
                        .value() +
                    m_config.get("database.name").value<std::string>().value())
                    .c_str(),
                &m_database,
                m_config.get("database.flags").value<int>().value(),
                m_config.get("database.zvfs")
                    .value<std::string>()
                    .value()
                    .c_str())) {
            throw exception::Initialize(sqlite3_errmsg(m_database));
        }

        m_worker_thread = std::thread(&Database::worker, this);
    }

    const bool Database::is_running() const
    {
        return m_running;
    }

    void Database::load_schema()
    {
        //     std::string schema_path =
        //         m_config.get("database.ddl.path").value<std::string>().value();
        //     std::string schema_file =
        //         m_config.get("database.ddl.main").value<std::string>().value();
        //     std::ifstream file(schema_path + "/" + schema_file);

        //     if (!file.is_open())
        //         throw exception::Initialize("Unable to open schema file");

        //     std::stringstream buffer;
        //     buffer << file.rdbuf();

        //     enqueue_sql(buffer.str());
    }

    void Database::load_migrations()
    {
        // std::string migration_path = m_config.get("database.ddl.migrations")
        //                                  .value<std::string>()
        //                                  .value();

        // for (const auto &entry : fs::directory_iterator(migration_path)) {
        //     if (!entry.is_regular_file())
        //         continue;

        //     std::ifstream file(entry.path());
        //     if (!file.is_open())
        //         continue;

        //     std::stringstream buffer;
        //     buffer << file.rdbuf();
        //     enqueue_sql(buffer.str());
    }
    // namespace engine::database

    void Database::enqueue_sql(const std::string &sql)
    {
        {
            std::lock_guard<std::mutex> lock(m_queue_mutex);
            m_sql_queue.push(sql);
        }
        m_queue_cv.notify_one();
    }

    void Database::worker()
    {
        while (m_running) {
            std::unique_lock<std::mutex> lock(m_queue_mutex);
            m_queue_cv.wait(
                lock, [this] { return !m_sql_queue.empty() || !m_running; });

            while (!m_sql_queue.empty()) {
                std::string sql = m_sql_queue.front();
                m_sql_queue.pop();
                lock.unlock();

                sqlite3_exec(
                    m_database, sql.c_str(), nullptr, nullptr, nullptr);

                lock.lock();
            }
        }
    }

    const bool Database::is_open() const
    {
        return m_database != nullptr;
    }

    void Database::exec_query_commit(const std::string &sql)
    {
        char *errmsg = nullptr;
        sqlite3_exec(m_database, "BEGIN;", nullptr, nullptr, nullptr);
        sqlite3_exec(m_database, sql.c_str(), nullptr, nullptr, &errmsg);
        sqlite3_exec(m_database, "COMMIT;", nullptr, nullptr, nullptr);
    }

    const int Database::exec_query(
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

    void Database::close() const
    {
        sqlite3_close_v2(m_database);
    }

    Database::~Database()
    {
        m_running = false;
        m_queue_cv.notify_all();
        if (m_worker_thread.joinable())
            m_worker_thread.join();

        Database::close();
    }
} // namespace engine::database