#pragma once

#include <ctime>
#include <engine/crypto/sha.hxx>
#include <engine/interfaces/iplugins.hxx>
#include <engine/magic/magic.hxx>
#include <engine/parser/json.hxx>
#include <engine/server/focades/data/metadata/entitys.hxx>
#include <functional>

namespace engine::focades::data
{
    class Metadata : public interface::IPlugins
    {
      public:
        Metadata() = default;
        ~Metadata() = default;

#ifdef ENGINE_PRO
        void register_plugins() override;
#endif

        void parse(const std::string &,
                   const std::function<void(metadata::record::DTO *)> &);

        [[nodiscard]] const engine::parser::Json dto_json(
            const metadata::record::DTO *);

      private:
        [[nodiscard]] const double compute_entropy(const std::string &);
        magic::Magic m_magic;
        crypto::Sha m_sha;
    };
} // namespace engine::focades::data