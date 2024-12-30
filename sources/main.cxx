#include <application/application.hxx>
#include <engine/llama/llama.hxx>

int main(int argc, char *argv[])
{
    application::Application application(argc, (const char **) argv);
    return application.run();
}