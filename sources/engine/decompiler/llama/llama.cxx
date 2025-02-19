#include <engine/decompiler/llama/llama.hxx>
#include <memory>

namespace engine
{
    namespace decompiler
    {
        Llama::~Llama()
        {
        }

        Llama::Llama(const std::string &p_model)
        {
            if (m_llama.load_model_file(p_model.c_str(),
                                   llama_model_default_params())) {
                m_llama.load_context(llama_context_default_params());
            }
        }

        const bool Llama::generate_decompiler_c(
            const std::string &p_buffer,
            const std::function<void(llama::record::CData *)> &p_callback)
        {
            return true;
        }
    } // namespace decompiler

} // namespace engine