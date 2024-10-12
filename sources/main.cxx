#include <program.hxx>

int main(int argc, char *argv[])
{
    fmt::print("     (\\(\\             (\\__/)\n"
               "     ( -.-) - yes...  (o.o ) - engine fast as a bunny!\n"
               "     o_(\")(\")         (\")(\")\n");

    program::Program program(argc, (const char **) argv);
    return program.run();
}