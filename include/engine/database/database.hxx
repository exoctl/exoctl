#pragma once

#include <engine/configuration/configuration.hxx>
#include <engine/database/entitys.hxx>
#include <engine/database/exception.hxx>
#include <engine/database/extend/database.hxx>
#include <engine/logging/logging.hxx>

#include <soci/mysql/soci-mysql.h>
#include <soci/postgresql/soci-postgresql.h>
#include <soci/soci.h>
#include <soci/sqlite3/soci-sqlite3.h>

#include <filesystem>
#include <fmt/core.h>
#include <fstream>

namespace engine::database
{
    class Database
    {
      public:
        Database() = default;
        ~Database() = default;

        Database(const Database &) = delete;
        Database &operator=(const Database &) = delete;

        friend extend::Database;

        void setup(const configuration::Configuration &,
                   const logging::Logging &);

        void load();
        static Soci& exec();
        static const std::vector<soci::row> query(const std::string &);
        static const bool is_table_exists(const std::string &);
        void close();
        
        static std::string type;
        
      private:
        configuration::Configuration config_;
        logging::Logging log_;

        static std::unique_ptr<Soci> session_;
        static std::string connection_str_;

        void load_schema();
        void load_migrations();

        template <typename ExceptionType>
        void load_sql_directory(const std::string &p_dir)
        {
            log_.info(fmt::format("Loading SQL files from '{}'", p_dir));

            for (const auto &entry :
                 std::filesystem::directory_iterator(p_dir)) {
                if (entry.is_directory())
                    load_sql_directory<ExceptionType>(entry.path().string());

                if (entry.path().extension() == ".sql") {
                    std::ifstream file(entry.path());
                    if (!file.is_open())
                        throw ExceptionType(fmt::format("Cannot open file '{}'",
                                                        entry.path().string()));

                    const std::string sql(
                        (std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());

                    exec() << sql;
                }
            }
        }
    };
} // namespace engine::database
