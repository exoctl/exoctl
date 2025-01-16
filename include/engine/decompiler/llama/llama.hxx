#pragma once

#include <engine/decompiler/llama/entitys.hxx>
#include <functional>
#include <engine/llama/llama.hxx>

#define PROMPT_DECOMPILER_C ""

namespace engine
{
    namespace decompiler
    {
        class Llama
        {
          public:
            Llama(const std::string &);
            ~Llama();

            const bool generate_decompiler_c(
                const std::string &,
                const std::function<void(llama::record::CData *)> &);

          private:
            ::engine::llama::Llama m_llama;
        };
    } // namespace decompiler
} // namespace engine