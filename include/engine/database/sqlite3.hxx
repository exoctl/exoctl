#pragma once

#include "idatabase.hxx"
#include "logging.hxx"
#include "parser/toml.hxx"

namespace engine
{
    namespace database
    {
        class Sqlite3 : public interface::IDatabase
        {
          public:
            Sqlite3();
            Sqlite3(Parser::Toml &, Logging::Log &);
            ~Sqlite3();

            [[nodiscard]] const bool open_db() const override;
            [[nodiscard]] const bool is_open_db() const override;
            void exec_query_commit(const std::string &) const override;
            void exec_query(const std::string &,
                            const std::function<void(void *)> &) const override;
            void close_db() const override;

          private:
            Logging::Log &m_log;
            Parser::Toml &m_config;
        };
    } // namespace database
} // namespace engine