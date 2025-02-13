#ifdef ENGINE_PRO

#pragma once

#include <engine/server/server.hxx>

namespace engine::server::bridge::_
{
    class Crow : public interface::ISubPlugins<Crow>
    {
      public:
        Crow() = default;
        ~Crow() = default;
        void _plugins() override;
    };
} // namespace engine::server::bridge::_

#endif