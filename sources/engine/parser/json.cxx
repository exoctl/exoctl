#include <engine/parser/json.hxx>

namespace Parser
{
Json::Json(const nlohmann::json &p_json) : m_json(p_json) {}
Json::Json() : m_json(0) {}
Json::~Json() {}

const std::string Json::json_to_string() { return m_json.dump(); }
void Json::json_craft(const nlohmann::json &p_json)
{
    m_json = p_json;
}
} // namespace Parser