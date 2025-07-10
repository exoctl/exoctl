#include <engine/engine.hxx>

int main()
{
    const std::string EXOCTLDIR = getenv("EXOCTLDIR");

    engine::configuration::Configuration config;
    engine::logging::Logging log;

    config.setup(EXOCTLDIR + "config/exoctl.ini");
    config.load();

    log.setup(config);
    log.load();

    engine::Engine engine;

    engine.setup(config, log);
    engine.load();

    engine.run();

    return EXIT_SUCCESS;
}