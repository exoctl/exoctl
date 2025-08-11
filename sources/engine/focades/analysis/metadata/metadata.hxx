#pragma once

#include <ctime>
#include <engine/focades/analysis/metadata/entitys.hxx>
#include <engine/crypto/sha.hxx>
#include <engine/interfaces/iplugins.hxx>
#include <engine/magic/magic.hxx>
#include <engine/parser/json/json.hxx>
#include <functional>

namespace engine::focades::analysis::metadata
{
    class Metadata : public interface::IPlugins<Metadata>
    {
      public:
        Metadata() = default;
        ~Metadata() = default;

        void _plugins() override;

        void parse(const std::string &,
                   const std::function<void(metadata::record::DTO *)> &);

        [[nodiscard]] const engine::parser::Json dto_json(
            const metadata::record::DTO *);

      private:
        [[nodiscard]] const double compute_entropy(const std::string &);
        magic::Magic m_magic;
        crypto::Sha m_sha;
    };
} // namespace engine::focades::analysis::metadata