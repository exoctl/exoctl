#include <application/application.hxx>

int main(int argc, char *argv[])
{
    application::Application application(argc, (const char **) argv);
    return application.run();
}