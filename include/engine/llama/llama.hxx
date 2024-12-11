#pragma once

#include <llama.h>
#include <string>

namespace engine
{
    class Llama
    {
      public:
        Llama();
        ~Llama();

        bool load_model(const std::string &, llama_model_params);
        bool load_context(llama_context_params);
        const std::string generate_text(const std::string &, int);

      private:
        llama_context *m_context;
        llama_model *m_model;
    };
} // namespace engine