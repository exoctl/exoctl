#include <engine/server/middlewares/cors/cors.hxx>

namespace engine::server::middlewares::cors
{
    void Cors::setup(configuration::Configuration &p_config)
    {
        m_config = &p_config;
    }

    void Cors::load()
    {
        this->global().origin(m_config->get("server.middleware.cors.origin")
                                  .value<std::string>()
                                  .value());
        if (!m_config->get("server.middleware.cors.enable")
                 .value<bool>()
                 .value()) {
            this->global().ignore();
        }
    }

} // namespace engine::server::middlewares::cors