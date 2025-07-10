#pragma once

#include <atomic>
#include <condition_variable>
#include <dirent.h>
#include <engine/configuration/configuration.hxx>
#include <engine/database/extend/database.hxx>
#include <engine/logging/logging.hxx>
#include <filesystem>
#include <fmt/core.h>
#include <queue>
#include <sqlite3.h>
#include <sys/types.h>

namespace engine::database
{
    class Database
    {
      public:
        Database();
        ~Database();
        Database(const Database &) = delete;
        Database &operator=(const Database &) = delete;

        friend extend::Database;

        void setup(const configuration::Configuration &,
                   const logging::Logging &);
        void load();
        void exec_query_commit(const std::string &);
        const int exec_query(const std::string &,
                             int (*)(void *, int, char **, char **),
                             char **p_msg);
        void close() const;

        std::atomic<bool> is_running;
        std::atomic<size_t> sql_queue_size;

      private:
        ::sqlite3 *m_database;
        configuration::Configuration m_config;
        logging::Logging m_log;

        void worker();
        void enqueue_sql(const std::string &&);
        void load_schema();
        void load_migrations();

        template <typename ExceptionType>
        void load_sql_directory(const std::string &&p_dir)
        {
            m_log.info(fmt::format("Loading from '{}'", p_dir));

            std::function<void(const std::string &)> process;
            process = [&](const std::string &p_path) {
                DIR *dir = opendir(p_path.c_str());
                if (!dir) {
                    throw ExceptionType(fmt::format(
                        "Failed to open '{}': {}", p_path, strerror(errno)));
                }

                while (const dirent *entry = readdir(dir)) {
                    const std::filesystem::path entry_name = entry->d_name;
                    const std::string full_path =
                        fmt::format("{}/{}", p_path, entry_name.c_str());

                    if (entry_name == "." || entry_name == "..")
                        continue;

                    if (entry_name.extension() == ".sql") {
                        m_log.info(fmt::format("{}", full_path));

                        std::ifstream file(full_path);
                        if (!file.is_open()) {
                            closedir(dir);
                            throw ExceptionType(fmt::format(
                                "Failed to open file '{}'", full_path));
                        }

                        const std::string sql(
                            (std::istreambuf_iterator<char>(file)),
                            std::istreambuf_iterator<char>());

                        Database::enqueue_sql(sql.data());
                    } else if (entry->d_type == DT_DIR) {
                        process(full_path);
                    }
                }

                closedir(dir);
            };

            process(p_dir);
        }

        std::thread m_worker_thread;
        std::mutex m_queue_mutex;
        std::condition_variable m_queue_cv;
        std::queue<std::string> m_sql_queue;
    };
} // namespace engine::database