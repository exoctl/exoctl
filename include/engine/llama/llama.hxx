#pragma once

#include <llama.h>
#include <string>

class Llama
{
  public:
    Llama();
    ~Llama() = default;

    bool load_model(const std::string &, llama_model_params);
    bool load_context(llama_context_params);

  private:
    llama_context *m_context;
    llama_model *m_model;
};