#define CROW_MAIN

#include <engine/disassembly/capstone/capstone.hxx>
#include <engine/engine.hxx>
#include <engine/engine_exception.hxx>
#include <engine/parser/elf.hxx>
#include <include/engine/security/signatures/signatures.hxx>

// clang-format off
#include <console.hxx> 
// clang-format on

int main()
{

    Parser::Toml configuration;
    TRY_BEGIN()
    configuration.toml_parser_file("configuration.toml");
    TRY_END()
    CATCH(std::exception, {
        CONSOLE_ERROR("Failed to load configuration: {}", e.what());
        return EXIT_FAILURE;
    })

    const std::string project_name =
        GET_TOML_TBL_VALUE(configuration, string, "project", "name");
    const std::string project_version =
        GET_TOML_TBL_VALUE(configuration, string, "project", "version");
    const std::string project_description =
        GET_TOML_TBL_VALUE(configuration, string, "project", "description");
    const std::string project_copyright =
        GET_TOML_TBL_VALUE(configuration, string, "project", "copyright");
    const std::string project_mode =
#if DEBUG
        "Debug";
#else
        "Realese";
#endif

    CONSOLE_INFO("Name        : {}", project_name);
    CONSOLE_INFO("Version     : {}", project_version);
    CONSOLE_INFO("Description : {}", project_description);
    CONSOLE_INFO("Copyright   : {}", project_copyright);
    CONSOLE_INFO("Mode        : {}", project_mode);

    CONSOLE_INFO(
        "Running engine with configuration from 'configuration.toml'...");

    Engine::Engine engine(configuration);

    TRY_BEGIN()

    CONSOLE_INFO("Starting engine...");
    engine.engine_run([&]() {
        for (const auto &route : engine.engine_routes()) {
            CONSOLE_INFO("Created route {} '{}' ",
                         (route.type == Crow::Types::Route::websocket)
                             ? "websocket"
                             : "web",
                         route.path);
        }
        CONSOLE_INFO(
            "Engine/{} Server is running at http://{}:{} using {} threads",
            project_mode,
            engine.engine_bindaddr(),
            engine.engine_port(),
            engine.engine_concurrency());
    });
    CONSOLE_INFO("Engine stopped successfully.");

    TRY_END()
    CATCH(Engine::EngineException::Run, {
        CONSOLE_ERROR("Engine encountered an error: {}", e.what());
        return EXIT_FAILURE;
    })

    CONSOLE_INFO("Exiting program.");
    return EXIT_SUCCESS;
}
