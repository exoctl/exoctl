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
            void add_member_string(const std::string &, const std::string &);
            void add_member_int(const std::string &, const int);
            void add_member_double(const std::string &, const double);
            void add_member_bool(const std::string &, const bool);
            void add_member_json(const std::string &, const Json &);
            void add_member_vector(const std::string &,
                                   const std::vector<Json> &);
            void add_member_uint16(const std::string &, const uint16_t);
            void add_member_uint64(const std::string &, const uint64_t);
            void clear();

            void from_string(const std::string &);

          private:
            rapidjson::MemoryPoolAllocator<rapidjson::CrtAllocator> m_allocator;
            rapidjson::Document m_document;
        };
    } // namespace parser
} // namespace engine