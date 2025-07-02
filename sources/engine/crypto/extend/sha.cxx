#include <engine/crypto/extend/sha.hxx>
#include <engine/crypto/sha.hxx>
#include <engine/plugins/plugins.hxx>

namespace engine::crypto::extend
{
    void Sha::bind_sha()
    {
        plugins::Plugins::lua.state.new_usertype<engine::crypto::Sha>(
            "Sha",
            sol::constructors<engine::crypto::Sha()>(),
            "sha1",
            &crypto::Sha::sha1,
            "sha256",
            &crypto::Sha::sha256,
            "sha512",
            &crypto::Sha::sha512,
            "sha224",
            &crypto::Sha::sha224,
            "sha384",
            &crypto::Sha::sha384,
            "sha3_256",
            &crypto::Sha::sha3_256,
            "sha3_512",
            &crypto::Sha::sha3_512);
    }

    void Sha::_plugins()
    {
        Sha::bind_sha();
    }
} // namespace engine::crypto::extend