#pragma once

#include <engine/interfaces/iplugins.hxx>

namespace engine::version::extend
{
    class Version : public interface::IPlugins<Version>
    {
      public:
        void _plugins() override;

      private:
        void bind_version();
    };
} // namespace engine::version::extend