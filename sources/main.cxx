#define CROW_MAIN

#include <engine/engine.hxx>
#include <engine/engine_exception.hxx>
#include <iostream>

int main(void)
{
    Parser::Toml configuration;
    configuration.toml_parser_file("configuration.toml");

    Engine::Engine engine(configuration);

    try
    {
        engine.engine_run();
    }
    catch (const Engine::EngineException::Run &e)
    {
        std::cerr << e.what() << std::endl;
    }

    return EXIT_SUCCESS;
}