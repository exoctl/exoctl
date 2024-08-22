#define CROW_MAIN

#include <engine/crow/crow.hxx>
#include <engine/crow/routes.hxx>
#include <engine/log.hxx>
#include <engine/database/postgresql.hxx>
#include <engine/parser/toml.hxx>

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