#pragma once

#include <ctime>
#include <engine/crow/focades/data/metadata_types.hxx>
#include <engine/crypto/sha.hxx>
#include <engine/magic/magic.hxx>
#include <engine/parser/json.hxx>
#include <functional>

namespace Focades
{
    namespace Data
    {
        class Metadata
        {
          public:
            Metadata();
            ~Metadata();

            void metadata_parse(const std::string &,
                                const std::function<void(Structs::DTO *)> &);

            [[nodiscard]] const Parser::Json metadata_dto_json(
                const Structs::DTO *);

          private:
            [[nodiscard]] const double metadata_compute_entropy(const std::string &);
            Magic::Magic m_magic;
            Crypto::Sha m_sha;
        };
    } // namespace Data
} // namespace Focades