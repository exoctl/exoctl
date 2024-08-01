#define CROW_MAIN

#include "crow/crow.hxx"
#include "crow/routes.hxx"
#include "toml.hxx"

int main(void)
{  
    Parser::Toml Toml;

    Toml.toml_parser_file("configuration.toml");

    Crow::CrowApi CrowApi("127.0.0.1", 40080);

    Crow::Routes Routes(CrowApi);

    Routes.create_routes();

    CrowApi.crow_run();
}