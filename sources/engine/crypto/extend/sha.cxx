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
            "gen_sha1_hash",
            &crypto::Sha::gen_sha1_hash,
            "gen_sha256_hash",
            &crypto::Sha::gen_sha256_hash,
            "gen_sha512_hash",
            &crypto::Sha::gen_sha512_hash,
            "gen_sha224_hash",
            &crypto::Sha::gen_sha224_hash,
            "gen_sha384_hash",
            &crypto::Sha::gen_sha384_hash,
            "gen_sha3_256_hash",
            &crypto::Sha::gen_sha3_256_hash,
            "gen_sha3_512_hash",
            &crypto::Sha::gen_sha3_512_hash);
    }

    void Sha::_plugins()
    {
        Sha::bind_sha();
    }
} // namespace engine::crypto::extend