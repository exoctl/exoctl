#pragma once

#include <engine/interfaces/iplugins.hxx>

namespace engine::crypto::extend
{
    class Sha : public interface::IPlugins<Sha>
    {
      public:
        void _plugins() override;

      private:
        void bind_sha();
    };
} // namespace engine::crypto::extend