#pragma once

namespace engine::interface
{
    class IPlugins
    {
      public:
        virtual ~IPlugins() = default;
        virtual void register_plugins() = 0;
    };

    template <typename Derived> class ISubPlugins
    {
      public:
        virtual ~ISubPlugins() = default;
        static inline void plugins()
        {
            Derived()._plugins();
        }

      private:
        virtual void _plugins() = 0;
    };
} // namespace engine::interface
