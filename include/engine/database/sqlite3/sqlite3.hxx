#pragma once

#include <engine/interfaces/idatabase.hxx>
#include <sqlite3.h>

namespace engine::database::sqlite3
{
    class Sqlite3 : public interface::IDatabase
    {
      public:
        Sqlite3() = default;
        ~Sqlite3();

        void setup(const std::string &, const int, const char * = nullptr);

        [[nodiscard]] const bool is_db_open() const override;
        void exec_db_query_commit(const std::string &);
        const int exec_db_query(
            const std::string &,
            const std::function<int(void *, int, char **, char **)> &);
        void close_db() const override;

      private:
        ::sqlite3 *m_database;
    };
} // namespace engine::database::sqlite3