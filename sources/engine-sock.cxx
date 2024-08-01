#define CROW_MAIN

#include "crow/crow.hxx"
#include "crow/routes.hxx"

int main(void)
{  
    Crow::CrowApi CrowApi("127.0.0.1", 40080);

    Crow::Routes Routes(CrowApi);

    Routes.create_routes();

    CrowApi.run();
}