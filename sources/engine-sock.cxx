#define CROW_MAIN

#include "crow/crow.hxx"
#include "crow/routes.hxx"
#include "toml.hxx"

int main(void)
{
    Parser::Toml Configuration;

    Configuration.toml_parser_file("configuration.toml");

    Crow::CrowApi CrowApi(GET_TOML_TBL_VALUE(Configuration, string, "crow", "bindaddr"),
                          GET_TOML_TBL_VALUE(Configuration, uint16_t, "crow", "port"));

    Crow::Routes Routes(CrowApi);

    Routes.routes_create();

    CrowApi.crow_run();
}