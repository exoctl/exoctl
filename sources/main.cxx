#include <application/application.hxx>
#include <fmt/core.h>

int main(int argc, char *argv[])
{
    application::Application application(argc, (const char **) argv);
    return application.run();
}