#define CROW_MAIN

#include "crow/crow.hxx"
#include "crow/routes.hxx"
#include "toml.hxx"
#include "database/postgresql/postgresql.hxx"

int main(void)
{
    Parser::Toml Configuration;
    Configuration.toml_parser_file("configuration.toml");

    try{
        Database::Postgresql Database(Configuration);
    }catch(pqxx::broken_connection&reason){
        CROW_LOG_INFO << reason.what();
    }

    Crow::Crow Crow(Configuration);
    
    Crow::Routes Routes(Crow);

    Routes.routes_create();

    Crow.crow_run();

    return 0;
}