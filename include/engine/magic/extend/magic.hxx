#ifdef ENGINE_PRO

#pragma once

#include <engine/interfaces/iplugins.hxx>

namespace engine::magic::extend
{
    class Magic : public interface::ISubPlugins<Magic>
    {
      public:
        void _plugins() override;

      private:
        void bind_magic();
    };
} // namespace engine::magic::extend

#endif