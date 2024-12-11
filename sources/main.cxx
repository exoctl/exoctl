#include <application/application.hxx>
#include <fmt/core.h>

void asscii_banner(void);

int main(int argc, char *argv[])
{
    asscii_banner();

    application::Application application(argc, (const char **) argv);
    return application.run();
}

void asscii_banner(void)
{
    fmt::print("                                        \n"
               "                   ..                   \n"
               "              .-=*###*=:                \n"
               "             -#@@@@@@@@%*:              \n"
               "           .*@@%%%%%%%%%@%=             \n"
               "          .+@%%%%%%%%%%%%@@=            \n"
               "          -@%%%%%%%%%%%%%%@%.           \n"
               "         .#@%%@@%%%%%%%@@%%@+           \n"
               "         :%%@@#%@%%%%@@#%@%@#.          \n"
               "         =@@%=..*@%%%%=.:+%@%:          \n"
               "         *@*.   .%@%@*    -%@-          \n"
               "         ##.    .#@%@=     =%+          \n"
               "         :.     .#@@@+      ::          \n"
               "                :%#+@*                  \n"
               "                +@= #%:                 \n"
               "           .:-=*@%. -@%+=-:.            \n"
               "         :*%%@@@@+  .#@@@@%#=.          \n"
               "        .#@@%%%%%:   =@%%%@@@=          \n"
               "        .%@%%%%@%.   -@%%%%%@*          \n"
               "        .%@%%%%@%:.:.=@%%%%%@*          \n"
               "        .#@%%@%%@##%#%%%@@%%@+          \n"
               "         *@@%%@@%@@@@%%@%%@@@-          \n"
               "         -#+:.-#@%%@%%@+.:=**.          \n"
               "               +@@%%@@%.                \n"
               "               -@%-.=@#                 \n"
               "               .*-   ++                 \n");
}