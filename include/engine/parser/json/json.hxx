#pragma once

#include <engine/interfaces/iplugins.hxx>
#include <engine/parser/json/exception.hxx>
#include <engine/parser/json/extend/json.hxx>
#include <optional>
#include <rapidjson/allocators.h>
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#include <stdint.h>
#include <string>
#include <vector>

namespace engine::parser::json
{
    class Json;

    class Json
    {
      public:
        Json();
        Json(const parser::json::Json &);
        ~Json() = default;

        Json &operator=(const Json &);

        friend class extend::Json;

        [[nodiscard]] std::string tostring() const;

        template <typename T>
        std::optional<T> get(const std::string &p_key) const
        {
            if (!document.HasMember(p_key.c_str())) {
                return std::nullopt;
            }

            const rapidjson::Value &v = document[p_key.c_str()];

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
                    jsonObj.document.CopyFrom(v, jsonObj.m_allocator, true);
                    return jsonObj;
                }
            } else if constexpr (std::is_same_v<T, std::vector<Json>>) {
                if (v.IsArray()) {
                    std::vector<Json> jsonArray;
                    jsonArray.reserve(v.Size());

                    for (const auto &item : v.GetArray()) {
                        Json jsonObj;
                        jsonObj.document.CopyFrom(
                            item, jsonObj.m_allocator, true);
                        jsonArray.push_back(std::move(jsonObj));
                    }
                    return jsonArray;
                }
            }

            return std::nullopt;
        }

        // Para arrays "soltos": json.add("foo").add("bar")
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
                v.CopyFrom(p_value.document, m_allocator);
            } else {
                throw exception::Add("Unsupported type");
            }

            if (!document.IsArray()) {
                document.SetArray();
            }

            document.PushBack(v, m_allocator);

            return *this;
        }

        template <typename T>
        Json add(const std::string &p_key, const T &p_value)
        {
            if (!document.IsObject()) {
                document.SetObject();
            }

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
                v.CopyFrom(p_value.document, m_allocator);
            } else if constexpr (std::is_same_v<T, std::vector<Json>>) {
                rapidjson::Value array(rapidjson::kArrayType);
                for (const auto &value : p_value) {
                    rapidjson::Value item;
                    item.CopyFrom(value.document, m_allocator);
                    array.PushBack(item, m_allocator);
                }
                document.AddMember(k, array, m_allocator);
                return *this;
            } else {
                throw exception::Add("Unsupported type");
            }

            document.AddMember(k, v, m_allocator);

            return *this;
        }

        void clear();
        void from_string(const std::string &);

        rapidjson::Document document;

      private:
        rapidjson::MemoryPoolAllocator<rapidjson::CrtAllocator> m_allocator;
    };
} // namespace engine::parser::json
