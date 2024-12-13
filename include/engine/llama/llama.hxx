#pragma once

#include <llama.h>
#include <string>
#include <engine/interfaces/iai.hxx>

namespace engine
{
    class Llama : public interface::IAi
    {
      public:
        Llama();
        ~Llama();

        const bool load_model(const char *p_path, ...) override;
        bool load_context(llama_context_params);
        const std::string generate_text(const std::string &, int);

      private:
        llama_context *m_context;
        llama_model *m_model;
    };
} // namespace engine