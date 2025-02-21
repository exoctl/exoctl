#pragma once

#include <engine/interfaces/iai.hxx>
#include <engine/interfaces/iplugins.hxx>
#include <llama.h>
#include <string>

namespace engine
{
    namespace llama
    {
        /*
This class is a warraper for llama, nothing more, I can use some native C llama
functions for C++ in the plugins and modify the name to fit the class
         */
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
            const bool load_context(const struct llama_context_params);
            void load_sampler(const struct llama_sampler_chain_params);
            void sampler_add(struct llama_sampler *);
            // const std::string prompt(const std::string &,
            //                          float = 0.8f,
            //                          float = 0.0f);
            void _plugins() override;

            /*
              wrappers
            */
            const struct llama_model_params load_model_default_params();
            const struct llama_context_params load_context_default_params();

          private:
            llama_context *m_context;
            llama_model *m_model;
            llama_sampler *m_sampler;
        };
    } // namespace llama
} // namespace engine