#pragma once

#include <ctime>
#include <engine/crowapp/focades/data/metadata/entitys.hxx>
#include <engine/crypto/sha.hxx>
#include <engine/magic/magic.hxx>
#include <engine/parser/json.hxx>
#include <functional>

namespace engine
{
    namespace focades
    {
        namespace data
        {
            class Metadata
            {
              public:
                Metadata();
                ~Metadata();

                void parse(
                    const std::string &,
                    const std::function<void(metadata::record::DTO *)> &);

                [[nodiscard]] const engine::parser::Json dto_json(
                    const metadata::record::DTO *);

              private:
                [[nodiscard]] const double compute_entropy(const std::string &);
                magic::Magic m_magic;
                crypto::Sha m_sha;
            };
        } // namespace data
    } // namespace focades
} // namespace engine