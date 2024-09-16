#define CROW_MAIN

#include <engine/disassembly/capstone/capstone.hxx>
#include <engine/engine.hxx>
#include <engine/engine_exception.hxx>
#include <include/engine/security/signatures/signatures.hxx>
#include <log.hxx> // this log not save in file

int main()
{
    Security::Sig signatures;

    signatures.sig_set_rule_mem("@include(\"elf\") @sig : \"elf_upx_packed\" { "
                                "elf.section.text.str_find(\"Upx 2023\") }",
                                "upx");

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
#if DEBUG
    LOG_INFO("Mode        : Debug");
#else 
    LOG_INFO("Mode        : Realese");
#endif

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
