#include <crypto/crypto.hxx>

BENCHMARK_DEFINE_F(CryptoBenchmark, ShaGenSha256Hash)(benchmark::State &state)
{
    std::string test_string = "the best engine";
    for (const auto _ : state) {
        std::string hash = sha->sha_gen_sha256_hash(test_string);
        benchmark::DoNotOptimize(hash);
    }
}

BENCHMARK_DEFINE_F(CryptoBenchmark, ShaGenSha3_256Hash)(benchmark::State &state)
{
    std::string test_string = "the best engine";
    for (const auto _ : state) {
        std::string hash = sha->sha_gen_sha3_256_hash(test_string);
        benchmark::DoNotOptimize(hash);
    }
}

BENCHMARK_DEFINE_F(CryptoBenchmark, ShaGenSha1Hash)(benchmark::State &state)
{
    std::string test_string = "the best engine";
    for (const auto _ : state) {
        std::string hash = sha->sha_gen_sha1_hash(test_string);
        benchmark::DoNotOptimize(hash);
    }
}

BENCHMARK_DEFINE_F(CryptoBenchmark, ShaGenSha224Hash)(benchmark::State &state)
{
    std::string test_string = "the best engine";
    for (const auto _ : state) {
        std::string hash = sha->sha_gen_sha224_hash(test_string);
        benchmark::DoNotOptimize(hash);
    }
}

BENCHMARK_DEFINE_F(CryptoBenchmark, ShaGenSha512Hash)(benchmark::State &state)
{
    std::string test_string = "the best engine";
    for (const auto _ : state) {
        std::string hash = sha->sha_gen_sha512_hash(test_string);
        benchmark::DoNotOptimize(hash);
    }
}

BENCHMARK_DEFINE_F(CryptoBenchmark, ShaGenSha3_512Hash)(benchmark::State &state)
{
    std::string test_string = "the best engine";
    for (const auto _ : state) {
        std::string hash = sha->sha_gen_sha3_512_hash(test_string);
        benchmark::DoNotOptimize(hash);
    }
}

BENCHMARK_DEFINE_F(CryptoBenchmark, ShaGenSha384Hash)(benchmark::State &state)
{
    std::string test_string = "the best engine";
    for (const auto _ : state) {
        std::string hash = sha->sha_gen_sha384_hash(test_string);
        benchmark::DoNotOptimize(hash);
    }
}

BENCHMARK_REGISTER_F(CryptoBenchmark, ShaGenSha256Hash);
BENCHMARK_REGISTER_F(CryptoBenchmark, ShaGenSha3_256Hash);
BENCHMARK_REGISTER_F(CryptoBenchmark, ShaGenSha1Hash);
BENCHMARK_REGISTER_F(CryptoBenchmark, ShaGenSha224Hash);
BENCHMARK_REGISTER_F(CryptoBenchmark, ShaGenSha512Hash);
BENCHMARK_REGISTER_F(CryptoBenchmark, ShaGenSha3_512Hash);
BENCHMARK_REGISTER_F(CryptoBenchmark, ShaGenSha384Hash);