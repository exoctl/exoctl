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
            model_ = llama_model_load_from_file(
                p_path, va_arg(ap, llama_model_params));

            va_end(ap);

            if (!model_) {
                return false;
            }

            return true;
        }

        const bool Llama::load_context(
            const struct llama_context_params p_params)
        {
            if (!model_) {
                return false;
            }

            context_ = llama_new_context_with_model(model_, p_params);

            if (!context_) {
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
            sampler_ = llama_sampler_chain_init(p_params);
        }

        // const std::string Llama::prompt(const std::string &prompt,
        //                                        float temperature,
        //                                        float min_p)
        //{
        // if (!model_) {
        //     throw std::runtime_error(
        //         "generate_text: Modelo não inicializado.");
        // }
        // if (!context_) {
        //     throw std::runtime_error(
        //         "generate_text: Contexto não inicializado.");
        // }
        //
        //// Tokeniza o prompt.
        // std::vector<llama_token> promptTokens =
        // llama_tokenize(model_, prompt.c_str(), true, true);
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
        //    int contextSize = llama_n_ctx(context_);
        //    int nCtxUsed = llama_get_kv_cache_used_cells(context_);
        //    if (nCtxUsed + batch.n_tokens > contextSize) {
        //        llama_sampler_free(sampler);
        //        throw std::runtime_error("Limite do contexto excedido.");
        //    }
        //
        //    // Executa a decodificação do modelo.
        //    if (llama_decode(context_, batch) < 0) {
        //        llama_sampler_free(sampler);
        //        throw std::runtime_error("Erro durante a decodificação.");
        //    }
        //
        //    // Amostra um token.
        //    llama_token currToken =
        //        llama_sampler_sample(sampler, context_, -1);
        //    if (llama_token_is_eog(model_, currToken)) {
        //        break; // Encerra ao encontrar o token de fim de geração.
        //    }
        //    std::string token_str =
        //    llama_token_to_piece(model_, currToken, true);
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
            if (context_) {
                llama_free(context_);
            }
            if (model_) {
                llama_model_free(model_);
            }
            if (sampler_) {
                llama_sampler_free(sampler_);
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