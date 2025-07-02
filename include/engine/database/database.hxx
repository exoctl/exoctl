#pragma once

#include <engine/configuration/configuration.hxx>
#include <sqlite3.h>

namespace engine::database
{
    class Database
    {
      public:
        Database() = default;
        ~Database();

        void setup(const configuration::Configuration &);
        void load();
        [[nodiscard]] const bool is_db_open() const;
        void exec_db_query_commit(const std::string &);
        const int exec_db_query(
            const std::string &,
            const std::function<int(void *, int, char **, char **)> &);
        void close_db() const;

      private:
        ::sqlite3 *m_database;
        configuration::Configuration m_config;
    };
} // namespace engine::database