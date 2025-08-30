#include <engine/crypto/extend/sha.hxx>
#include <engine/crypto/sha.hxx>
#include <engine/plugins/plugins.hxx>

namespace engine::crypto::extend
{
    void Sha::bind_sha()
    {
        plugins::Plugins::lua.state.new_usertype<engine::crypto::Sha>(
            "Sha",
            "new",
            sol::constructors<engine::crypto::Sha()>(),
            "sha1",
            [](crypto::Sha &self, const std::string &buff) {
                return self.sha1(buff);
            },
            "sha256",
            [](crypto::Sha &self, const std::string &buff) {
                return self.sha256(buff);
            },
            "sha512",
            [](crypto::Sha &self, const std::string &buff) {
                return self.sha512(buff);
            },
            "sha224",
            [](crypto::Sha &self, const std::string &buff) {
                return self.sha224(buff);
            },
            "sha384",
            [](crypto::Sha &self, const std::string &buff) {
                return self.sha384(buff);
            },
            "sha3_256",
            [](crypto::Sha &self, const std::string &buff) {
                return self.sha3_256(buff);
            },
            "sha3_512",
            [](crypto::Sha &self, const std::string &buff) {
                return self.sha3_512(buff);
            });
    }

    void Sha::_plugins()
    {
        Sha::bind_sha();
    }
} // namespace engine::crypto::extend