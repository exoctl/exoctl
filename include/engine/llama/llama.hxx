#pragma once

#include <engine/interfaces/iai.hxx>
#include <engine/interfaces/iplugins.hxx>
#include <llama.h>
#include <string>

namespace engine
{
    namespace llama
    {
        class Llama : public interface::IAi
#ifdef ENGINE_PRO
            ,
                      public interface::ISubPlugins<Llama>
#endif
        {
          public:
            Llama() = default;
            ~Llama();

            const bool load_model_file(const char *p_path, ...) override;
            bool load_context(llama_context_params);
            const std::string generate_text(const std::string &, int);

            void _plugins() override;
          private:
            llama_context *m_context;
            llama_model *m_model;
        };
    } // namespace llama
} // namespace engine