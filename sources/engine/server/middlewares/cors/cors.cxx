#include <engine/server/middlewares/cors/cors.hxx>

namespace engine::server::middlewares::cors
{
    void Cors::setup(configuration::Configuration &p_config)
    {
        m_config = &p_config;
    }

    void Cors::load()
    {
        this->global()
            .headers("X-Custom-Header", "Upgrade-Insecure-Requests")
            .methods("POST"_method, "GET"_method)
            .prefix("/cors")
            .origin("example.com")
            .prefix("/nocors")
            .ignore();
    }

} // namespace engine::server::middlewares::cors