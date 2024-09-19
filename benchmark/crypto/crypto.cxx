#include <crypto/crypto.hxx>

BENCHMARK_DEFINE_F(CryptoBenchmark, ShaGenSha256Hash)(benchmark::State &state)
{
    std::string test_string = "the best engine";
    for (auto _ : state) {
        std::string hash = sha->sha_gen_sha256_hash(test_string);
        benchmark::DoNotOptimize(hash);
    }
}

BENCHMARK_REGISTER_F(CryptoBenchmark, ShaGenSha256Hash);
