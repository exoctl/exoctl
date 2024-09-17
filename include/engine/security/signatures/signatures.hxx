#pragma once

#include <engine/parser/elf.hxx>
#include <engine/security/signatures/lexer/lexer.hxx>
#include <engine/security/signatures/signatures_types.hxx>
#include <functional>
#include <unordered_map>

namespace Security
{

    extern "C" {
    struct rule {
        const char *name;
        const char *name_space;
    };

    struct include {
        const char *name;
        void *obj;
    };
    }

    class Sig
    {
      public:
        Sig();
        ~Sig();

        Types::SigError_t sig_set_rule_mem(const std::string &,
                                           const std::string &);
        Types::SigError_t sig_set_rule_file(const std::string &,
                                            const std::string &);
        void sig_scan_file(const std::string &);
        void sig_scan_mem(const std::string &);
        void sig_create_handler_obj(const std::string &, void *);

      private:
        LexerToken m_current_token;
        Lexer m_lexer;
        Parser::Elf m_elf;

        static std::unordered_map<std::string_view, void *> m_objs;
        static std::unordered_map<std::string_view, rule> m_rules;
        // static std::unordered_map<SigRule, Include> m_includes;

        void sig_parser_syntax(const std::string &);
        void sig_parser_includes(const std::function<void(const char *)> &);
        void sig_parser_sigrule();
        bool sig_includes_check(const std::string &);
        void sig_advance_token();
        bool sig_expect_token(Types::LexerToken);
        void sig_init_objs_includes();
    };
} // namespace Security