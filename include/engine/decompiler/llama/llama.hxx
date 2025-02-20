#pragma once

#include <engine/decompiler/llama/entitys.hxx>
#include <engine/llama/llama.hxx>
#include <functional>

namespace engine::decompiler
{
    class Llama
    {
      public:
        Llama(const std::string &);
        ~Llama() = default;

        const bool generate_decompiler_c(
            const std::string &,
            const std::function<void(llama::record::CData *)> &);

      private:
        ::engine::llama::Llama m_llama;
    };
} // namespace engine::decompiler
