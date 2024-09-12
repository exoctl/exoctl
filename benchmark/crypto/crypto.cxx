#include <crypto/crypto.hxx>

BENCHMARK_DEFINE_F(CryptoBenchmark, ShaGenSha256Hash)(benchmark::State &state)
{
    std::string test_string = "the best engine";
    for (auto _ : state)
    {
        sha->sha_gen_sha256_hash(test_string);
        std::string hash = sha->sha_get_sha256_hash();
        benchmark::DoNotOptimize(hash);
    }
}

BENCHMARK_REGISTER_F(CryptoBenchmark, ShaGenSha256Hash);
