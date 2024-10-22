#include <program/program.hxx>

int main(int argc, char *argv[])
{
    fmt::print(
        "\033[35m     (\\(\\            \033[0m\033[37m(\\__/)\n"
        "\033[35m     ( -.-) - \033[36myes...\033[0m \033[37m(o.o )\033[32m - "
        "engine fast as a bunny!\n" // Texto em ciano e partes do coelho em
                                    // branco
        "\033[35m     o_(\")(\")        \033[0m\033[37m(\")(\")\n\033[0m");

    program::Program program(argc, (const char **) argv);
    return program.run();
}