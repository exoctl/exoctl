#pragma once

#include <ctime>
#include <engine/bridge/focades/data/metadata/entitys.hxx>
#include <engine/crypto/sha.hxx>
#include <engine/interfaces/iplugins.hxx>
#include <engine/magic/magic.hxx>
#include <engine/parser/json/json.hxx>
#include <functional>

namespace engine::bridge::focades::data::metadata
{
    class Metadata
#ifdef ENGINE_PRO
        : public interface::ISubPlugins<Metadata>
#endif
    {
      public:
        Metadata() = default;
        ~Metadata() = default;

#ifdef ENGINE_PRO
        void _plugins() override;
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
} // namespace engine::bridge::focades::data::metadata