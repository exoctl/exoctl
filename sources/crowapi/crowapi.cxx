#include "crow.hxx"
#include "routes.hxx"

int main(void)
{  
    Crow::CrowApi CrowApi(8080);

    Crow::Routes Routes(CrowApi);

    Routes.create_routes();

    CrowApi.run();
}