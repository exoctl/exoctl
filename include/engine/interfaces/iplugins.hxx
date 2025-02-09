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

        template <typename Derived> class ISubPlugins
        {
          public:
            virtual ~ISubPlugins() = default;
            static inline void plugins()
            {
                Derived()._plugins();
            }

          private:
            virtual const int _plugins() = 0;
        };
    } // namespace interface
} // namespace engine