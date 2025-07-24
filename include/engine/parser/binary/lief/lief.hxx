#pragma once

#include <LIEF/LIEF.hpp>
#include <LIEF/json.hpp>
#include <cstdint>
#include <engine/parser/binary/lief/exception.hxx>
#include <functional>
#include <memory>
#include <netdb.h>
#include <string>

namespace engine::parser::binary
{
    /**
     * @class LIEF
     * @brief Template-based parser for different binary types using LIEF.
     * @tparam BinaryType The specific binary type from LIEF (e.g.,
     * LIEF::PE::Binary).
     */
    template <typename BinaryType, typename ParserType> class LIEF
    {
      public:
        LIEF() = default;
        ~LIEF() = default;

        /**
         * @brief Parses binary data from a byte buffer.
         * @param buffer The byte buffer containing binary data.
         * @param callback Function to handle the parsed binary object.
         */
        void parse_bytes(
            const std::string &p_buffer,
            const std::function<void(std::unique_ptr<const BinaryType>)>
                &p_callback)
        {
            std::vector<uint8_t> raw(p_buffer.begin(), p_buffer.end());
            auto binary = ParserType::parse(raw);
            if (!binary) {
                throw lief::exception::Parser("Error parser binary");
            }
            p_callback(std::move(binary));
        }
        /**
         * @brief Parses a binary from a file path.
         * @param  Path to the binary file.
         * @param  Function to handle the parsed binary object.
         */
        void parse_file(
            const std::string &p_filepath,
            const std::function<void(std::unique_ptr<const BinaryType>)>
                &p_callback)
        {
            auto binary = ParserType::parse(p_filepath);
            if (!binary) {
                throw lief::exception::Parser("Error parser binary");
            }
            p_callback(std::move(binary));
        }
    };
} // namespace engine::parser::binary
