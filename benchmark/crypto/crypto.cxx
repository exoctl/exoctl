#include <benchmark/benchmark.h>
#include <crypto/crypto.hxx>
#include <fmt/format.h>

BENCHMARK_DEFINE_F(CryptoBenchmark, ShaGenSha256Hash)(benchmark::State &state)
{
    std::string test_string = fmt::format("{}", state.range(0));

    for (const auto _ : state) {
        std::string hash = sha->gen_sha256_hash(test_string);
        benchmark::DoNotOptimize(hash);
    }

    state.SetBytesProcessed(static_cast<int64_t>(state.iterations()) *
                            static_cast<int64_t>(test_string.size()));
}

BENCHMARK_DEFINE_F(CryptoBenchmark, ShaGenSha3_256Hash)(benchmark::State &state)
{
    std::string test_string = fmt::format("{}", state.range(0));

    for (const auto _ : state) {
        std::string hash = sha->gen_sha3_256_hash(test_string);
        benchmark::DoNotOptimize(hash);
    }

    state.SetBytesProcessed(static_cast<int64_t>(state.iterations()) *
                            static_cast<int64_t>(test_string.size()));
}

BENCHMARK_DEFINE_F(CryptoBenchmark, ShaGenSha1Hash)(benchmark::State &state)
{
    std::string test_string = fmt::format("{}", state.range(0));

    for (const auto _ : state) {
        std::string hash = sha->gen_sha1_hash(test_string);
        benchmark::DoNotOptimize(hash);
    }

    state.SetBytesProcessed(static_cast<int64_t>(state.iterations()) *
                            static_cast<int64_t>(test_string.size()));
}

BENCHMARK_DEFINE_F(CryptoBenchmark, ShaGenSha224Hash)(benchmark::State &state)
{
    std::string test_string = fmt::format("{}", state.range(0));

    for (const auto _ : state) {
        std::string hash = sha->gen_sha224_hash(test_string);
        benchmark::DoNotOptimize(hash);
    }

    state.SetBytesProcessed(static_cast<int64_t>(state.iterations()) *
                            static_cast<int64_t>(test_string.size()));
}

BENCHMARK_DEFINE_F(CryptoBenchmark, ShaGenSha512Hash)(benchmark::State &state)
{
    std::string test_string = fmt::format("{}", state.range(0));

    for (const auto _ : state) {
        std::string hash = sha->gen_sha512_hash(test_string);
        benchmark::DoNotOptimize(hash);
    }

    state.SetBytesProcessed(static_cast<int64_t>(state.iterations()) *
                            static_cast<int64_t>(test_string.size()));
}

BENCHMARK_DEFINE_F(CryptoBenchmark, ShaGenSha3_512Hash)(benchmark::State &state)
{
    std::string test_string = fmt::format("{}", state.range(0));

    for (const auto _ : state) {
        std::string hash = sha->gen_sha3_512_hash(test_string);
        benchmark::DoNotOptimize(hash);
    }

    state.SetBytesProcessed(static_cast<int64_t>(state.iterations()) *
                            static_cast<int64_t>(test_string.size()));
}

BENCHMARK_DEFINE_F(CryptoBenchmark, ShaGenSha384Hash)(benchmark::State &state)
{
    std::string test_string = fmt::format("{}", state.range(0));

    for (const auto _ : state) {
        std::string hash = sha->gen_sha384_hash(test_string);
        benchmark::DoNotOptimize(hash);
    }

    state.SetBytesProcessed(static_cast<int64_t>(state.iterations()) *
                            static_cast<int64_t>(test_string.size()));
}

BENCHMARK_REGISTER_F(CryptoBenchmark, ShaGenSha256Hash)
    ->Arg(16)
    ->Arg(64)
    ->Arg(256)
    ->Arg(1024)
    ->Arg(4096);

BENCHMARK_REGISTER_F(CryptoBenchmark, ShaGenSha3_256Hash)
    ->Arg(16)
    ->Arg(64)
    ->Arg(256)
    ->Arg(1024)
    ->Arg(4096);

BENCHMARK_REGISTER_F(CryptoBenchmark, ShaGenSha1Hash)
    ->Arg(16)
    ->Arg(64)
    ->Arg(256)
    ->Arg(1024)
    ->Arg(4096);

BENCHMARK_REGISTER_F(CryptoBenchmark, ShaGenSha224Hash)
    ->Arg(16)
    ->Arg(64)
    ->Arg(256)
    ->Arg(1024)
    ->Arg(4096);

BENCHMARK_REGISTER_F(CryptoBenchmark, ShaGenSha512Hash)
    ->Arg(16)
    ->Arg(64)
    ->Arg(256)
    ->Arg(1024)
    ->Arg(4096);

BENCHMARK_REGISTER_F(CryptoBenchmark, ShaGenSha3_512Hash)
    ->Arg(16)
    ->Arg(64)
    ->Arg(256)
    ->Arg(1024)
    ->Arg(4096);

BENCHMARK_REGISTER_F(CryptoBenchmark, ShaGenSha384Hash)
    ->Arg(16)
    ->Arg(64)
    ->Arg(256)
    ->Arg(1024)
    ->Arg(4096);