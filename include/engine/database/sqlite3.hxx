#pragma once

#include "idatabase.hxx"
#include "log.hxx"
#include "parser/toml.hxx"

namespace Database
{
class Sqlite3 : public Interfaces::IDatabase
{
  public:
    Sqlite3();
    Sqlite3(Parser::Toml &, Logging::Log &);
    ~Sqlite3();

    /* if not use Postgresql(const std::string &) open_db return false */
    const bool open_db() const override;
    const bool is_open_db() const override;
    const void exec_query_commit(const std::string &) const override;
    const void exec_query(const std::string &,
                          const std::function<void(void *)> &) const override;
    const void close_db() const override;

  private:
    Logging::Log &m_log;
    Parser::Toml &m_config;
};
} // namespace Database