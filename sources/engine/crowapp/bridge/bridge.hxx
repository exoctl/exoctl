#pragma once

#include <engine/crowapp/bridge/entitys.hxx>
#include <engine/crowapp/bridge/gateway/analysis.hxx>
#include <engine/crowapp/bridge/gateway/data.hxx>
#include <engine/crowapp/crowapp.hxx>
#include <functional>
#include <memory>
#include <utility>
#include <vector>

namespace crowapp
{
    class Bridge
    {
      public:
        Bridge(CrowApp &);
        ~Bridge();

        void load();
        const std::vector<bridge::record::Bridge> &get_endpoints();

      private:
        CrowApp &m_crowapp;
        std::vector<bridge::record::Bridge> m_endpoints;

        std::unique_ptr<bridge::Analysis> m_analysis;
        std::unique_ptr<bridge::Data> m_data;

        // std::unique_ptr<crowapp::bridge::WebSocket> m_socket_scan_yara;
        // std::unique_ptr<crowapp::bridge::WebSocket> m_socket_parser_elf;
        // std::unique_ptr<crowapp::bridge::WebSocket> m_socket_metadata;
        // std::unique_ptr<crowapp::bridge::WebSocket> m_socket_clamav;
        // std::unique_ptr<crowapp::bridge::WebSocket>
        //     m_socket_capstone_disass_x86_64;
        // std::unique_ptr<crowapp::bridge::WebSocket>
        //     m_socket_capstone_disass_arm_64;
        // std::unique_ptr<crowapp::bridge::Web<>> m_web_endpoins;

        // std::unique_ptr<focades::parser::binary::ELF> m_parser_elf;
        // std::unique_ptr<focades::analysis::scan::Yara> m_scan_yara;
        // std::unique_ptr<focades::analysis::scan::Clamav> m_scan_clamav;
        // std::unique_ptr<focades::rev::disassembly::Capstone>
        // m_capstone_x86_64;
        // std::unique_ptr<focades::rev::disassembly::Capstone>
        // m_capstone_arm_64; std::unique_ptr<focades::data::Metadata>
        // m_metadata;

        // void update_endpoints();
        // void parser_elf();
        // void metadata();
        // void scan_yara();
        // void capstone_disass_x86_64();
        // void capstone_disass_arm_64();
        // void scan_clamav();

        /* Routes generate for debug */
#ifdef DEBUG
        // void endpoint();
#endif
    };
} // namespace crowapp
