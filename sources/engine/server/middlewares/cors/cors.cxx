#include <engine/server/middlewares/cors/cors.hxx>

namespace engine::server::middlewares::cors
{
    void Cors::setup(configuration::Configuration &p_config)
    {
        config_ = &p_config;
    }

    void Cors::load()
    {
        this->global().origin(config_->get("server.middleware.cors.origin")
                                  .value<std::string>()
                                  .value());
        this->global().max_age(config_->get("server.middleware.cors.max_age")
                                   .value<uint32_t>()
                                   .value());
        if (!config_->get("server.middleware.cors.enable")
                 .value<bool>()
                 .value()) {
            this->global().ignore();
        }
    }

} // namespace engine::server::middlewares::cors