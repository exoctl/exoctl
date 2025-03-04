#include <engine/llama/exception.hxx>
#include <engine/llama/llama.hxx>
#include <engine/plugins/plugins.hxx>
#include <string>
#include <vector>

namespace engine
{
    namespace llama
    {
        const bool Llama::load_model_file(const char *p_path, ...)
        {
            va_list ap;
            va_start(ap, p_path);
            m_model = llama_model_load_from_file(
                p_path, va_arg(ap, llama_model_params));

            va_end(ap);

            if (!m_model) {
                return false;
            }

            return true;
        }

        const bool Llama::load_context(
            const struct llama_context_params p_params)
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

        void Llama::sampler_add(struct llama_sampler *)
        {
        }

        void Llama::load_sampler(
            const struct llama_sampler_chain_params p_params)
        {
            m_sampler = llama_sampler_chain_init(p_params);
        }

        // const std::string Llama::prompt(const std::string &prompt,
        //                                        float temperature,
        //                                        float min_p)
        //{
        // if (!m_model) {
        //     throw std::runtime_error(
        //         "generate_text: Modelo não inicializado.");
        // }
        // if (!m_context) {
        //     throw std::runtime_error(
        //         "generate_text: Contexto não inicializado.");
        // }
        //
        //// Tokeniza o prompt.
        // std::vector<llama_token> promptTokens =
        // llama_tokenize(m_model, prompt.c_str(), true, true);
        //
        //// Prepara o batch inicial com o prompt.
        // llama_batch batch;
        // batch.token = promptTokens.data();
        // batch.n_tokens = promptTokens.size();
        //
        //// Inicializa o sampler com os parâmetros desejados.
        // llama_sampler_chain_params samplerParams =
        //     llama_sampler_chain_default_params();
        // samplerParams.no_perf = true;
        // llama_sampler *sampler = llama_sampler_chain_init(samplerParams);
        // llama_sampler_chain_add(sampler,
        //                         llama_sampler_init_min_p(min_p, 1));
        // llama_sampler_chain_add(sampler,
        //                         llama_sampler_init_temp(temperature));
        // llama_sampler_chain_add(
        //     sampler, llama_sampler_init_dist(LLAMA_DEFAULT_SEED));
        //
        // std::string resposta;
        // while (true) {
        //    // Verifica se o contexto ainda comporta novos tokens.
        //    int contextSize = llama_n_ctx(m_context);
        //    int nCtxUsed = llama_get_kv_cache_used_cells(m_context);
        //    if (nCtxUsed + batch.n_tokens > contextSize) {
        //        llama_sampler_free(sampler);
        //        throw std::runtime_error("Limite do contexto excedido.");
        //    }
        //
        //    // Executa a decodificação do modelo.
        //    if (llama_decode(m_context, batch) < 0) {
        //        llama_sampler_free(sampler);
        //        throw std::runtime_error("Erro durante a decodificação.");
        //    }
        //
        //    // Amostra um token.
        //    llama_token currToken =
        //        llama_sampler_sample(sampler, m_context, -1);
        //    if (llama_token_is_eog(m_model, currToken)) {
        //        break; // Encerra ao encontrar o token de fim de geração.
        //    }
        //    std::string token_str =
        //    llama_token_to_piece(m_model, currToken, true);
        //    resposta += token_str;
        //
        //    // Atualiza o batch para processar apenas o novo token.
        //    batch.token = &currToken;
        //    batch.n_tokens = 1;
        //}
        // llama_sampler_free(sampler);
        // return resposta;
        //    "";
        //}

        Llama::~Llama()
        {
            if (m_context) {
                llama_free(m_context);
            }
            if (m_model) {
                llama_model_free(m_model);
            }
            if (m_sampler) {
                llama_sampler_free(m_sampler);
            }
        }

        const struct llama_model_params Llama::load_model_default_params()
        {
            return llama_model_default_params();
        }

        const struct llama_context_params Llama::load_context_default_params()
        {
            return llama_context_default_params();
        }
    } // namespace llama
} // namespace engine