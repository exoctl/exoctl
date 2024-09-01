#define CROW_MAIN

#include <engine/engine.hxx>
#include <engine/engine_exception.hxx>
#include <include/engine/security/signatures/lexer/lexer.hxx>
#include <iostream>
#include <log.hxx> // this log not save in file

int main()
{
    Security::Lexer lexer;
    
    lexer.lexer_parser(
        "@include(\"elf\")  \"upx\" {  { elf.text.str_find(\"Upx 2023\") }");

    Security::LexerToken token = lexer.lexer_next_token();

    std::cout << token.value << std::endl;
 
    Parser::Toml configuration;
    try
    {
        configuration.toml_parser_file("configuration.toml");
    }
    catch (const std::exception &e)
    {
        LOG_ERROR("Failed to load configuration: {}", e.what());
        return EXIT_FAILURE;
    }

    const std::string project_name =
        GET_TOML_TBL_VALUE(configuration, string, "project", "name");
    const std::string project_version =
        GET_TOML_TBL_VALUE(configuration, string, "project", "version");
    const std::string project_description =
        GET_TOML_TBL_VALUE(configuration, string, "project", "description");
    const std::string project_copyright =
        GET_TOML_TBL_VALUE(configuration, string, "project", "copyright");

    LOG_INFO("Name        : {}", project_name);
    LOG_INFO("Version     : {}", project_version);
    LOG_INFO("Description : {}", project_description);
    LOG_INFO("Copyright   : {}", project_copyright);
    LOG_INFO("Running engine with configuration from 'configuration.toml'...");

    Engine::Engine engine(configuration);

    try
    {
        LOG_INFO("Started engine.");
        engine.engine_run();
        LOG_INFO("Engine stopped successfully.");
    }
    catch (const Engine::EngineException::Run &e)
    {
        LOG_ERROR("Engine encountered an error: {}", e.what());
        return EXIT_FAILURE;
    }

    LOG_INFO("Exiting program.");
    return EXIT_SUCCESS;
}
