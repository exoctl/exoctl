#pragma once

#include <engine/bridge/focades/reverse/disassembly/capstone/entitys.hxx>
#include <engine/disassembly/capstone/capstone.hxx>
#include <engine/parser/json/json.hxx>

namespace engine::bridge::focades::reverse::disassembly::capstone
{
    class Capstone
    {
      public:
        Capstone(const cs_arch, const cs_mode);
        ~Capstone() = default;

        void disassembly(const std::string &,
                         const std::function<void(capstone::record::DTO *)> &);

        ::engine::parser::Json dto_json(const capstone::record::DTO *);

      private:
        ::engine::disassembly::Capstone m_capstone;
        const std::string m_arch;
        const std::string m_mode;
    };
} // namespace engine::bridge::focades::reverse::disassembly::capstone
