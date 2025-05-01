#pragma once

#include <engine/interfaces/iplugins.hxx>

namespace engine::parser::extend
{
    class Json : public interface::ISubPlugins<Json>
    {
      public:
        void _plugins() override;

      private:
        void bind_json();
    };
} // namespace engine::parser::extend
