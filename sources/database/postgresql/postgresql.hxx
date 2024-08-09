#pragma once

#include "idbconn.hxx"
#include "toml.hxx"

#include <pqxx/pqxx>

namespace Database
{
    class Postgresql : public IDB
    {
    public:
        Postgresql();
        Postgresql(Parser::Toml &);
        ~Postgresql();

        /* if not use Postgresql(const std::string &) open_db return false */ 
        const bool open_db() const override; 
        const bool is_open_db() const override;
        const void exec_query_commit(const std::string &) const override;
        const void close_db() const override;


    private:;
        mutable pqxx::connection m_conn;
        Parser::Toml &m_config;
    };
}