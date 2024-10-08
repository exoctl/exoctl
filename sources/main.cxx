#define CROW_MAIN

#include <engine/configuration/configuration.hxx>
#include <engine/disassembly/capstone/capstone.hxx>
#include <engine/engine.hxx>
#include <engine/exception.hxx>
#include <engine/logging.hxx>

void pr_banner()
{
    fmt::print("     (\\(\\             (\\__/)\n"
               "     ( -.-) - yes...  (o.o ) - engine fast as a bunny!\n"
               "     o_(\")(\")         (\")(\")\n");
}

int main()
{
    pr_banner();

    configuration::Configuration config("configuration.toml");

    TRY_BEGIN()
    config.load(); 
    TRY_END()
    CATCH(std::exception, {
        fmt::print(stderr, "Failed to load configuration: {}\n", e.what());
        return EXIT_FAILURE;
    })

    logging::Logging log(config);

    LOG(log, info, "Name        : {}", config.get_project().name);
    LOG(log, info, "Version     : {}", config.get_project().version);
    LOG(log, info, "Description : {}", config.get_project().description);
    LOG(log, info, "Copyright   : {}", config.get_project().copyright);
    LOG(log,
        info,
        "Mode        : {}",
#if DEBUG
        "Debug");
#else
        "Release");
#endif

    LOG(log,
        info,
        "Running engine with configuration from '{}'...",
        config.get_path_config());

    engine::Engine engine(config, log);

    TRY_BEGIN()

    LOG(log, info, "Starting engine...");
    engine.run();
    LOG(log, info, "Engine stopped successfully.");

    TRY_END()
    CATCH(engine::exception::Run, {
        LOG(log, error, "Engine encountered an error: {}", e.what());
        return EXIT_FAILURE;
    })

    LOG(log, info, "Exiting program.");
    return EXIT_SUCCESS;
}
