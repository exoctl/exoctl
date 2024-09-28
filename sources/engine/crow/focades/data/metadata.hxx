#pragma once

#include <ctime>
#include <engine/crow/focades/data/metadata_types.hxx>
#include <engine/crypto/sha.hxx>
#include <engine/magic/magic.hxx>
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

            const void metadata_parse(
                const std::string &,
                const std::function<void(Structs::DTO *)> &);

          private:
            const double metadata_compute_entropy(const std::string &);
            Magic::Magic m_magic;
            Crypto::Sha m_sha;
        };
    } // namespace Data
} // namespace Focades