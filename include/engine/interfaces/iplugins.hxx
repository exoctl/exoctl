#pragma once

namespace engine::interface
{
    template <typename Derived> class IPlugins
    {
      public:
        virtual ~IPlugins() = default;
        static inline void plugins()
        {
            Derived()._plugins();
        }

      private:
        virtual void _plugins() = 0;
    };
} // namespace engine::interface
