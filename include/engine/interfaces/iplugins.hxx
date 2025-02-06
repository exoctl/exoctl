#pragma once

namespace engine
{
    namespace interface
    {
        class IPlugins
        {
          public:
            virtual ~IPlugins() = default;
            virtual void register_plugins() = 0;
        };
    } // namespace interface
} // namespace engine