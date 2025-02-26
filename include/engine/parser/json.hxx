#pragma once

#include <engine/interfaces/iplugins.hxx>
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
        class Json
#ifdef ENGINE_PRO
            : public interface::ISubPlugins<Json>
#endif
        {
          public:
            Json();
            Json(const parser::Json &);
            ~Json() = default;

#ifdef ENGINE_PRO
            void _plugins() override;
#endif
            [[nodiscard]] std::string to_string() const;

            template <typename T>
            void add_member(const std::string &p_key, const T &p_value)
            {
                rapidjson::Value k(p_key.c_str(), m_allocator);
                rapidjson::Value v;

                if constexpr (std::is_same_v<T, std::string>) {
                    v.SetString(p_value.c_str(), m_allocator);
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
                    return;
                } else {
                    throw std::runtime_error("Unsupported type");
                }

                m_document.AddMember(k, v, m_allocator);
            }
            void clear();

            void from_string(const std::string &);

          private:
            rapidjson::MemoryPoolAllocator<rapidjson::CrtAllocator> m_allocator;
            rapidjson::Document m_document;
        };
    } // namespace parser
} // namespace engine