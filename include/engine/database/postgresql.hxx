#pragma once

#include <engine/interfaces/idatabase.hxx>
#include <engine/log.hxx>
#include <engine/parser/toml.hxx>
#include <pqxx/pqxx>

namespace Database
{
class Postgresql : public IDatabase
{
  public:
    Postgresql();
    Postgresql(Parser::Toml &, Logging::Log &);
    ~Postgresql();

    /* if not use Postgresql(const std::string &) open_db return false */
    const bool open_db() const override;
    const bool is_open_db() const override;
    const void exec_query_commit(const std::string &) const override;
    const void exec_query(const std::string &,
                          const std::function<void(void *)> &) const override;
    const void close_db() const override;

  private:
    Logging::Log &m_log;
    mutable pqxx::connection m_conn;
    Parser::Toml &m_config;
};
} // namespace Database