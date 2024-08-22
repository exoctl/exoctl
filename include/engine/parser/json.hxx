#pragma once

#include <nlohmann/json.hpp>

namespace Parser
{
class Json
{
  public:
    Json(const nlohmann::json &);
    Json();
    ~Json();

    const std::string json_to_string();
    void json_craft(const nlohmann::json &p_json);

  private:
    nlohmann::json m_json;
};
}; // namespace Parser