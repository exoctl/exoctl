#define CROW_MAIN

#include "crow/crow.hxx"
#include "crow/routes.hxx"
#include "toml.hxx"
#include "database/postgresql/postgresql.hxx"
#include "log.hxx"

int main(void)
{
    Parser::Toml Configuration;
    Configuration.toml_parser_file("configuration.toml");

    Logging::Log Log(Configuration);

    try
    {
        Database::Postgresql Database(Configuration, Log);
    }
    catch (const pqxx::broken_connection &reason)
    {
        LOG(Log, warn, "'{:s}' : {:s}", reason.location.function_name(), reason.what());
    }

    Crow::Crow Crow(Configuration);

    Crow::Routes Routes(Crow);

    Routes.routes_create();

    Crow.crow_run();

    return 0;
}