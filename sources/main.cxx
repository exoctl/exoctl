#include <application/application.hxx>
#include <engine/plugins/plugins.hxx>
#include <iostream>

int main(int argc, char *argv[])
{
    application::Application application(argc, (const char **) argv);
    return application.run();
}