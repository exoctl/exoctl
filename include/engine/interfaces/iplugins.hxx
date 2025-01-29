#pragma once 


namespace engine
{
    namespace interface
    {
        class IPlugins
        {
          protected:
            virtual ~IPlugins() = default;
            virtual void register_plugins() = 0;
        };
    } // namespace interface
} // namespace engine