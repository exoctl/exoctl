#include <engine/llama/llama.hxx>

Llama::Llama()
{
}

bool Llama::load_model(const std::string &path, llama_model_params p_params)
{
    m_model = llama_load_model_from_file(path.c_str(), p_params);

    if (!m_model)
        return false;

    return true;
}

bool Llama::load_context(llama_context_params p_params)
{
    if (!m_model)
        return false;
    
    m_context = llama_new_context_with_model(m_model, p_params);

    if (!m_context)
        return false;

    return true;
}