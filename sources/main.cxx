#define CROW_MAIN

#include <engine/engine.hxx>

int main(void)
{

    Parser::Toml configuration;
    configuration.toml_parser_file("configuration.toml");

    Engine::Engine engine(configuration);

    engine.engine_run();
    
    return EXIT_SUCCESS;
}