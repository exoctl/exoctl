#pragma once

#include <engine/interfaces/iplugins.hxx>
#include <engine/parser/json/extend/json.hxx>
#include <optional>
#include <rapidjson/allocators.h>
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#include <stdint.h>
#include <string>
#include <vector>

namespace engine
{
    namespace parser
    {
        class Json;

        class Json
        {
          public:
            Json();
            Json(const parser::Json &);
            ~Json() = default;
            Json &operator=(const Json &other)
            {
                if (this != &other) {
                    m_document.SetObject();
                    m_document.CopyFrom(other.m_document, m_allocator);
                }
                return *this;
            }
            friend class extend::Json;

            [[nodiscard]] std::string tostring() const;

            template <typename T>
            std::optional<T> get(const std::string &p_key) const
            {
                if (!m_document.HasMember(p_key.c_str())) {
                    return std::nullopt;
                }

                const rapidjson::Value &v = m_document[p_key.c_str()];

                if constexpr (std::is_same_v<T, std::string>) {
                    if (v.IsString())
                        return std::string(v.GetString());
                } else if constexpr (std::is_same_v<T, int>) {
                    if (v.IsInt())
                        return v.GetInt();
                } else if constexpr (std::is_same_v<T, uint16_t>) {
                    if (v.IsUint())
                        return static_cast<uint16_t>(v.GetUint());
                } else if constexpr (std::is_same_v<T, uint64_t>) {
                    if (v.IsUint64())
                        return v.GetUint64();
                } else if constexpr (std::is_same_v<T, int16_t>) {
                    if (v.IsInt())
                        return static_cast<int16_t>(v.GetInt());
                } else if constexpr (std::is_same_v<T, int64_t>) {
                    if (v.IsInt64())
                        return v.GetInt64();
                } else if constexpr (std::is_same_v<T, double>) {
                    if (v.IsDouble())
                        return v.GetDouble();
                } else if constexpr (std::is_same_v<T, bool>) {
                    if (v.IsBool())
                        return v.GetBool();
                } else if constexpr (std::is_same_v<T, Json>) {
                    if (v.IsObject()) {
                        Json jsonObj;
                        jsonObj.m_document.CopyFrom(
                            v, jsonObj.m_allocator, true);

                        return std::move(jsonObj);
                    }
                } else if constexpr (std::is_same_v<T, std::vector<Json>>) {
                    if (v.IsArray()) {
                        std::vector<Json> jsonArray;
                        jsonArray.reserve(v.Size());

                        for (const auto &item : v.GetArray()) {
                            Json jsonObj;
                            jsonObj.m_document.CopyFrom(
                                item, jsonObj.m_allocator, true);
                            jsonArray.push_back(std::move(jsonObj));
                        }
                        return std::move(jsonArray);
                    }
                }

                return std::nullopt;
            }

            template <typename T> Json add(const T &p_value)
            {
                rapidjson::Value v;

                if constexpr (std::is_same_v<T, std::string>) {
                    v.SetString(p_value.c_str(), m_allocator);
                } else if constexpr (std::is_same_v<T, const char *>) {
                    v.SetString(p_value, m_allocator);
                } else if constexpr (std::is_same_v<T, int>) {
                    v.SetInt(p_value);
                } else if constexpr (std::is_same_v<T, uint16_t>) {
                    v.SetUint(p_value);
                } else if constexpr (std::is_same_v<T, uint64_t>) {
                    v.SetUint64(p_value);
                } else if constexpr (std::is_same_v<T, int16_t>) {
                    v.SetInt(p_value);
                } else if constexpr (std::is_same_v<T, int64_t>) {
                    v.SetInt64(p_value);
                } else if constexpr (std::is_same_v<T, double>) {
                    v.SetDouble(p_value);
                } else if constexpr (std::is_same_v<T, bool>) {
                    v.SetBool(p_value);
                } else if constexpr (std::is_same_v<T, Json>) {
                    v.CopyFrom(p_value.m_document, m_allocator);
                } else {
                    throw std::runtime_error("Unsupported type");
                }

                if (!m_document.IsArray()) {
                    rapidjson::Value array(rapidjson::kArrayType);
                    if (m_document.IsObject() && !m_document.ObjectEmpty()) {
                        array.PushBack(rapidjson::Value().CopyFrom(m_document,
                                                                   m_allocator),
                                       m_allocator);
                    }
                    m_document.Swap(array);
                }

                m_document.PushBack(v, m_allocator);

                return *this;
            }

            template <typename T>
            Json add(const std::string &p_key, const T &p_value)
            {
                rapidjson::Value k(p_key.c_str(), m_allocator);
                rapidjson::Value v;

                if constexpr (std::is_same_v<T, std::string>) {
                    v.SetString(p_value.c_str(), m_allocator);
                } else if constexpr (std::is_same_v<T, const char *>) {
                    v.SetString(p_value, m_allocator);
                } else if constexpr (std::is_same_v<T, int>) {
                    v.SetInt(p_value);
                } else if constexpr (std::is_same_v<T, uint16_t>) {
                    v.SetUint(p_value);
                } else if constexpr (std::is_same_v<T, uint64_t>) {
                    v.SetUint64(p_value);
                } else if constexpr (std::is_same_v<T, int16_t>) {
                    v.SetInt(p_value);
                } else if constexpr (std::is_same_v<T, int64_t>) {
                    v.SetInt64(p_value);
                } else if constexpr (std::is_same_v<T, double>) {
                    v.SetDouble(p_value);
                } else if constexpr (std::is_same_v<T, bool>) {
                    v.SetBool(p_value);
                } else if constexpr (std::is_same_v<T, Json>) {
                    v.CopyFrom(p_value.m_document, m_allocator);
                } else if constexpr (std::is_same_v<T, std::vector<Json>>) {
                    rapidjson::Value array(rapidjson::kArrayType);
                    for (const auto &value : p_value) {
                        rapidjson::Value item;
                        item.CopyFrom(value.m_document, m_allocator);
                        array.PushBack(item, m_allocator);
                    }
                    m_document.AddMember(k, array, m_allocator);
                    return *this;
                } else {
                    throw std::runtime_error("Unsupported type");
                }

                m_document.AddMember(k, v, m_allocator);

                return *this;
            }
            void clear();

            void from_string(const std::string &);

          private:
            rapidjson::MemoryPoolAllocator<rapidjson::CrtAllocator> m_allocator;
            rapidjson::Document m_document;
        };
    } // namespace parser
} // namespace engine