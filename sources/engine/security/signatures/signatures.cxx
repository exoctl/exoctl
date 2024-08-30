#include <engine/security/signatures/signatures.hxx>

namespace Security
{
Sig::Sig() {}
Sig::~Sig() {}

Types::SigError Sig::sig_set_rule_mem(const std::string &p_rule)
{

    return Types::SigError::ERROR_SUCCESS;
}
Types::SigError Sig::sig_set_rule_file(const std::string &p_rule)
{
    return Types::SigError::ERROR_SUCCESS;
}

void Sig::sig_parser_syntax(const std::string &p_rule) {}
void Sig::sig_identify_import(const std::string &) {}
void Sig::sig_parser_sigrule(const std::string &) {}
} // namespace Security