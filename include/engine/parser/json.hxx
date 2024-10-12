#pragma once

#include <rapidjson/allocators.h>
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#include <stdint.h>
#include <string>
#include <vector>

namespace parser
{
    class Json
    {
      public:
        Json();
        Json(const parser::Json &);
        ~Json();

        [[nodiscard]] std::string to_string() const;
        void add_member_string(const std::string &, const std::string &);
        void add_member_int(const std::string &, const int);
        void add_member_double(const std::string &, const double);
        void add_member_bool(const std::string &, const bool);
        void add_member_json(const std::string &, const Json &);
        void add_member_vector(const std::string &, const std::vector<Json> &);
        void add_member_uint16(const std::string &, const uint16_t);
        void add_member_uint64(const std::string &, const uint64_t);
        void clear();

        [[nodiscard]] rapidjson::Document &get_document();

      private:
        rapidjson::MemoryPoolAllocator<rapidjson::CrtAllocator> m_allocator;
        rapidjson::Document m_document;
    };
} // namespace parser