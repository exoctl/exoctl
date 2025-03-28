#pragma once

#include <engine/bridge/focades/reverse/disassembly/capstone/entitys.hxx>
#include <engine/disassembly/capstone/capstone.hxx>
#include <engine/parser/json/json.hxx>

namespace engine::bridge::focades::reverse::disassembly::capstone
{
    class Capstone
    {
      public:
        Capstone() = default;
        ~Capstone() = default;
        
        void setup(const cs_arch, const cs_mode);
        void disassembly(const std::string &,
                         const std::function<void(capstone::record::DTO *)> &);

        ::engine::parser::Json dto_json(const capstone::record::DTO *);

      private:
        ::engine::disassembly::Capstone m_capstone;
        std::string m_arch;
        std::string m_mode;
    };
} // namespace engine::bridge::focades::reverse::disassembly::capstone
