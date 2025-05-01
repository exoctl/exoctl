#pragma once

#include <engine/interfaces/iai.hxx>
#include <engine/interfaces/iplugins.hxx>
#include <engine/llama/extend/llama.hxx>
#include <llama.h>
#include <string>

namespace engine
{
    namespace llama
    {
        class Llama;

        class Llama : public interface::IAi
        {
          public:
            Llama() = default;
            ~Llama();

            friend class extend::Llama;

            const bool load_model_file(const char *p_path, ...) override;
            const bool load_context(const struct llama_context_params);
            void load_sampler(const struct llama_sampler_chain_params);
            void sampler_add(struct llama_sampler *);
            // const std::string prompt(const std::string &,
            //                          float = 0.8f,
            //                          float = 0.0f);
            static const struct llama_model_params load_model_default_params();
            static const struct llama_context_params load_context_default_params();

          private:
            llama_context *m_context;
            llama_model *m_model;
            llama_sampler *m_sampler;
        };
    } // namespace llama
} // namespace engine