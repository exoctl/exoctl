#pragma once

#include <ctime>
#include <engine/crypto/sha.hxx>
#include <engine/focades/analysis/metadata/entitys.hxx>
#include <engine/magic/magic.hxx>
#include <engine/parser/json/json.hxx>
#include <functional>

namespace engine::focades::analysis::metadata
{
    class Metadata
    {
      public:
        Metadata() = default;
        ~Metadata() = default;

        void parse(const std::string &,
                   const std::function<void(metadata::record::DTO *)> &);

        [[nodiscard]] const engine::parser::json::Json dto_json(
            const metadata::record::DTO *);

        magic::Magic magic;
        crypto::Sha sha;

      private:
        [[nodiscard]] const double compute_entropy(const std::string &);
    };
} // namespace engine::focades::analysis::metadata