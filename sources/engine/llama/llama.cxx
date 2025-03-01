#include <engine/llama/exception.hxx>
#include <engine/llama/llama.hxx>
#include <engine/plugins/plugins.hxx>
#include <stdexcept>
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

#ifdef ENGINE_PRO
        void Llama::_plugins()
        {
            plugins::Plugins::lua.state.new_usertype<llama_model_params>(
                "llama_model_params",
                sol::constructors<llama_model_params()>(),
                "n_gpu_layers",
                &llama_model_params::n_gpu_layers,
                "split_mode",
                &llama_model_params::split_mode,
                "main_gpu",
                &llama_model_params::main_gpu,
                "tensor_split",
                &llama_model_params::tensor_split,
                "rpc_servers",
                &llama_model_params::rpc_servers,
                "progress_callback",
                &llama_model_params::progress_callback,
                "progress_callback_user_data",
                &llama_model_params::progress_callback_user_data,
                "kv_overrides",
                &llama_model_params::kv_overrides,
                "vocab_only",
                &llama_model_params::vocab_only,
                "use_mmap",
                &llama_model_params::use_mmap,
                "use_mlock",
                &llama_model_params::use_mlock,
                "check_tensors",
                &llama_model_params::check_tensors);

            plugins::Plugins::lua.state.new_usertype<llama_context_params>(
                "llama_context_params",
                sol::constructors<llama_context_params()>(),
                "n_ctx",
                &llama_context_params::n_ctx,
                "n_batch",
                &llama_context_params::n_batch,
                "n_ubatch",
                &llama_context_params::n_ubatch,
                "n_seq_max",
                &llama_context_params::n_seq_max,
                "n_threads",
                &llama_context_params::n_threads,
                "n_threads_batch",
                &llama_context_params::n_threads_batch,
                "rope_scaling_type",
                &llama_context_params::rope_scaling_type,
                "pooling_type",
                &llama_context_params::pooling_type,
                "attention_type",
                &llama_context_params::attention_type,
                "rope_freq_base",
                &llama_context_params::rope_freq_base,
                "rope_freq_scale",
                &llama_context_params::rope_freq_scale,
                "yarn_ext_factor",
                &llama_context_params::yarn_ext_factor,
                "yarn_attn_factor",
                &llama_context_params::yarn_attn_factor,
                "yarn_beta_fast",
                &llama_context_params::yarn_beta_fast,
                "yarn_beta_slow",
                &llama_context_params::yarn_beta_slow,
                "yarn_orig_ctx",
                &llama_context_params::yarn_orig_ctx,
                "defrag_thold",
                &llama_context_params::defrag_thold,
                "cb_eval",
                &llama_context_params::cb_eval,
                "cb_eval_user_data",
                &llama_context_params::cb_eval_user_data,
                "type_k",
                &llama_context_params::type_k,
                "type_v",
                &llama_context_params::type_v,
                "logits_all",
                &llama_context_params::logits_all,
                "embeddings",
                &llama_context_params::embeddings,
                "offload_kqv",
                &llama_context_params::offload_kqv,
                "flash_attn",
                &llama_context_params::flash_attn,
                "no_perf",
                &llama_context_params::no_perf,
                "abort_callback",
                &llama_context_params::abort_callback,
                "abort_callback_data",
                &llama_context_params::abort_callback_data);

            plugins::Plugins::lua.state.new_usertype<Llama>(
                "Llama",
                "load_sampler",
                [](Llama &self,
                   sol::optional<llama_sampler_chain_params> opt_params)
                    -> void {
                    llama_sampler_chain_params params;
                    if (opt_params) {
                        params = opt_params.value();
                    } else {
                        params = llama_sampler_chain_default_params();
                    }
                    self.load_sampler(params);
                },
                "load_model_default_params",
                load_model_default_params,
                "load_context_default_params",
                load_context_default_params,
                "load_model_file",
                [](Llama &self,
                   const char *p_path,
                   sol::optional<llama_model_params> opt_params) -> bool {
                    llama_model_params params;
                    if (opt_params) {
                        params = opt_params.value();
                    } else {
                        params = llama_model_default_params();
                    }
                    return self.load_model_file(p_path, params);
                },
                "load_context",
                [](Llama &self,
                   sol::optional<llama_context_params> opt_params) -> bool {
                    llama_context_params params;
                    if (opt_params) {
                        params = opt_params.value();
                    } else {
                        params = llama_context_default_params();
                    }
                    return self.load_context(params);
                });
        }
#endif
    } // namespace llama
} // namespace engine