#pragma once

#include <atomic>
#include <condition_variable>
#include <engine/configuration/configuration.hxx>
#include <engine/database/extend/database.hxx>
#include <engine/logging/logging.hxx>
#include <queue>
#include <sqlite3.h>

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
        const int exec_query(
            const std::string &,
            const std::function<int(void *, int, char **, char **)> &);
        void close() const;

        std::atomic<bool> is_running;
        std::atomic<size_t> sql_queue_size;

      private:
        ::sqlite3 *m_database;
        configuration::Configuration m_config;
        logging::Logging m_log;

        void worker();
        void enqueue_sql(const std::string &sql);
        void load_schema();
        void load_migrations();

        std::thread m_worker_thread;
        std::mutex m_queue_mutex;
        std::condition_variable m_queue_cv;
        std::queue<std::string> m_sql_queue;
    };
} // namespace engine::database