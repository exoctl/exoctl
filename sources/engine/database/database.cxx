#include <dirent.h>
#include <engine/database/database.hxx>
#include <engine/database/exception.hxx>
#include <filesystem>
#include <fmt/core.h>
#include <sys/types.h>

namespace engine::database
{
    Database::Database()
        : is_running(true), m_database(nullptr), sql_queue_size(0)
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
        const std::string root_path =
            m_config.get("database.ddl.path").value<std::string>().value() +
            m_config.get("database.ddl.migrations")
                .value<std::string>()
                .value();

        m_log.info(fmt::format("Loading migrations from '{}'", root_path));

        auto process_directory = [&](const std::string &p_path,
                                     auto &&self_ref) -> void {
            DIR *dir = opendir(p_path.c_str());
            if (!dir) {
                throw std::runtime_error(fmt::format(
                    "Failed to open '{}': {}", p_path, strerror(errno)));
            }

            const struct dirent *entry;
            while ((entry = readdir(dir)) != nullptr) {
                const std::filesystem::path entry_name = entry->d_name;
                const std::string full_path =
                    fmt::format("{}/{}", p_path, entry_name.c_str());

                if (entry_name == "." || entry_name == "..") {
                    continue;
                }

                if (entry_name.extension() == ".sql") {
                    m_log.info(
                        fmt::format("Applying migration: {}", full_path));

                    std::ifstream file(full_path);
                    if (!file.is_open()) {
                        closedir(dir);
                        throw std::runtime_error(fmt::format(
                            "Failed to open migration file '{}'", full_path));
                    }

                    std::stringstream buffer;
                    buffer << file.rdbuf();
                    const std::string sql = buffer.str();

                    Database::enqueue_sql(sql);

                } else if (entry->d_type == DT_DIR) {
                    self_ref(full_path, self_ref);
                }
            }

            closedir(dir);
        };

        process_directory(root_path, process_directory);
    }

    void Database::enqueue_sql(const std::string &sql)
    {
        m_log.info(fmt::format("Enqueueing SQL: {}", sql));
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

                m_log.info(fmt::format(
                    "Executing SQL from queue({}): {} ", sql_queue_size.load(), sql));

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
        int (*p_callback)(void *, int, char **, char **))
    {
        m_log.info(fmt::format("Executing SQL query: {}", p_sql));
        return sqlite3_exec(m_database, p_sql.c_str(), p_callback, 0, nullptr);
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
