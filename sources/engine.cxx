#define CROW_MAIN

#include <engine/crow/crow.hxx>
#include <engine/crow/routes.hxx>
#include <engine/log.hxx>
#include <engine/database/postgresql.hxx>
#include <engine/parser/toml.hxx>

int main(void)
{
    Parser::Toml configuration;
    configuration.toml_parser_file("configuration.toml");
    Logging::Log log(configuration);

    try
    {
        Database::Postgresql database(configuration, log);
    }
    catch (const pqxx::broken_connection &reason)
    {
        LOG(log, warn, "'{:s}'", reason.what());
    }

    Crow::Crow crow(configuration, log);
    Crow::Routes routes(crow);
    routes.routes_create();
    crow.crow_run();

    return EXIT_SUCCESS;
}