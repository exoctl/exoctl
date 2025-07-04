#pragma once

#include <atomic>
#include <condition_variable>
#include <engine/configuration/configuration.hxx>
#include <engine/database/extend/database.hxx>
#include <queue>
#include <sqlite3.h>

namespace engine::database
{
    class Database
    {
      public:
        Database() = default;
        ~Database();

        friend extend::Database;

        void setup(const configuration::Configuration &);
        void load();
        [[nodiscard]] const bool is_open() const;
        [[nodiscard]] const bool is_running() const;
        void exec_query_commit(const std::string &);
        const int exec_query(
            const std::string &,
            const std::function<int(void *, int, char **, char **)> &);
        void close() const;

      private:
        ::sqlite3 *m_database;
        configuration::Configuration m_config;

        void worker();
        void enqueue_sql(const std::string &sql);
        void load_schema();
        void load_migrations();

        std::thread m_worker_thread;
        std::mutex m_queue_mutex;
        std::condition_variable m_queue_cv;
        std::queue<std::string> m_sql_queue;
        std::atomic<bool> m_running = true;
    };
} // namespace engine::database