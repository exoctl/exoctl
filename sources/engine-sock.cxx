#define CROW_MAIN

#include "crow/crow.hxx"
#include "crow/routes.hxx"
#include "toml.hxx"

int main(void)
{
    Parser::Toml Configuration;
    
    const std::string config_file = "configuration.toml";
    CROW_LOG_INFO << "Parsing this file '" << config_file << "' for configuration";

    Configuration.toml_parser_file(config_file);

    Crow::CrowApi CrowApi(GET_TOML_TBL_VALUE(Configuration, string, "crow", "bindaddr"),
                          GET_TOML_TBL_VALUE(Configuration, uint16_t, "crow", "port"));

    Crow::Routes Routes(CrowApi);

    Routes.routes_create();

    CrowApi.crow_run();
}