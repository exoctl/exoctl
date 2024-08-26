#include <engine/parser/json.hxx>

namespace Parser
{
Json::Json() {}
Json::Json(const nlohmann::json &p_json) : nlohmann::json(p_json) {}

std::string Json::json_to_string() const { return dump(); }
void Json::json_craft(const nlohmann::json &p_json) { *this = p_json; }
} // namespace Parser