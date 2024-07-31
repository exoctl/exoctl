#include "crow.hxx"
#include "routes.hxx"

int main(void)
{  
    Crow::CrowApi CrowApi(100);

    Crow::Routes Routes(CrowApi);

    CrowApi.run();
}