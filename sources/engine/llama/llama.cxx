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

            int n_prompt = llama_tokenize(m_model,
                                          p_prompt.c_str(),
                                          p_prompt.size(),
                                          nullptr,
                                          0,
                                          true,
                                          true);

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
                llama_model_free(m_model);
            }
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
                "load_model_default_params",
                llama_model_default_params,
                "load_context_default_params",
                llama_context_default_params,
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