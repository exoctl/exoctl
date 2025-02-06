#ifdef ENGINE_PRO

#pragma once

#include <engine/server/server.hxx>

namespace engine::server::bridge::_
{
    class Crow : public interface::IPlugins
    {
      public:
        Crow() = default;
        ~Crow() = default;
        void register_plugins() override;
        static void plugins();
    };
} // namespace engine::server::bridge::_

#endif