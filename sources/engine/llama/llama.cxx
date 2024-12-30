#include <engine/llama/exception.hxx>
#include <engine/llama/llama.hxx>
#include <llama/common/log.h>
#include <stdexcept>
#include <string>
#include <vector>

namespace engine
{
    Llama::Llama()
    {
    }

    const bool Llama::load_model(const char *p_path, ...)
    {
        va_list ap;
        va_start(ap, p_path);
        m_model =
            llama_load_model_from_file(p_path, va_arg(ap, llama_model_params));

        va_end(ap);

        if (!m_model) {
            return false;
        }

        return true;
    }

    bool Llama::load_context(llama_context_params p_params)
    {
        if (!m_model) {
            return false;
        }

        m_context = llama_new_context_with_model(m_model, p_params);

        if (!m_context) {
            return false;
        }

        return true;
    }

    const std::string Llama::generate_text(const std::string &p_prompt,
                                           int max_tokens)
    {
        if (!m_model) {
            throw llama::exception::GenerateMessage(
                "Model is not initialized.");
        }

        if (!m_context) {
            throw llama::exception::GenerateMessage(
                "Context is not initialized.");
        }

        int n_prompt = llama_tokenize(
            m_model, p_prompt.c_str(), p_prompt.size(), nullptr, 0, true, true);

        if (n_prompt <= 0) {
            throw llama::exception::GenerateMessage(
                "Failed to tokenize prompt.");
        }

        std::vector<llama_token> prompt_tokens(n_prompt);
        n_prompt = llama_tokenize(m_model,
                                  p_prompt.c_str(),
                                  p_prompt.size(),
                                  prompt_tokens.data(),
                                  n_prompt,
                                  true,
                                  true);

        if (n_prompt <= 0) {
            throw llama::exception::GenerateMessage(
                "Error during prompt tokenization.");
        }

        return "";
    }

    Llama::~Llama()
    {
        if (m_context) {
            llama_free(m_context);
        }
        if (m_model) {
            llama_free_model(m_model);
        }
    }

} // namespace engine