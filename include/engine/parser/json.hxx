#pragma once

#include <nlohmann/json.hpp>

namespace Parser
{
class Json : public nlohmann::json
{
  public:
    Json();
    Json(const nlohmann::json &);

    std::string json_to_string() const;
    void json_craft(const nlohmann::json &);

    ~Json() = default;
};
} // namespace Parser
