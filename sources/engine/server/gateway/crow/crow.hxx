#ifdef ENGINE_PRO

#pragma once

#include <engine/interfaces/iplugins.hxx>

namespace engine::server::gateway
{
    class Crow : public interface::ISubPlugins<Crow>
    {
      public:
        Crow() = default;
        ~Crow() = default;
        void _plugins() override;
    };
} // namespace engine::server::gateway

#endif