#pragma once

#include <engine/interfaces/iplugins.hxx>

namespace engine::llama::extend
{
    class Llama : public interface::ISubPlugins<Llama>
    {
      public:
        void _plugins() override;

      private:
        void bind_llama();
        void bind_context();
        void bind_model();
    };
} // namespace engine::llama::extend