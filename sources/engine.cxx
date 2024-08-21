#define CROW_MAIN

#include "crow/crow.hxx"
#include "crow/routes.hxx"
#include "log.hxx"
#include "postgresql.hxx"
#include "toml.hxx"

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
        LOG(Log, warn, "'{:s}'", reason.what());
    }

    Crow::Crow Crow(Configuration, Log);
    Crow::Routes Routes(Crow);
    Routes.routes_create();
    Crow.crow_run();

    return EXIT_SUCCESS;
}