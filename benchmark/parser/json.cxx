#include <benchmark/benchmark.h>
#include <parser/json.hxx>
#include <vector>

BENCHMARK_DEFINE_F(JsonBenchmark, JsonAddMemberString)(benchmark::State &state)
{
    for (const auto _ : state) {
        json->add_member("name", "maldec");
        benchmark::DoNotOptimize(json);
    }
}

BENCHMARK_DEFINE_F(JsonBenchmark, JsonAddMemberInt)(benchmark::State &state)
{
    for (const auto _ : state) {
        json->add_member("age", 21);
        benchmark::DoNotOptimize(json);
    }
}

BENCHMARK_DEFINE_F(JsonBenchmark, JsonAddMemberDouble)(benchmark::State &state)
{
    for (const auto _ : state) {
        json->add_member("score", 99.5);
        benchmark::DoNotOptimize(json);
    }
}

BENCHMARK_DEFINE_F(JsonBenchmark, JsonAddMemberBool)(benchmark::State &state)
{
    for (const auto _ : state) {
        json->add_member("is_active", true);
        benchmark::DoNotOptimize(json);
    }
}

BENCHMARK_DEFINE_F(JsonBenchmark, JsonAddMemberJson)(benchmark::State &state)
{
    engine::parser::Json json_2;

    json_2.add_member("is_match", true);

    for (const auto _ : state) {
        json->add_member("json", json_2);
        benchmark::DoNotOptimize(json);
    }
}

BENCHMARK_DEFINE_F(JsonBenchmark, JsonAddMemberUInt16)(benchmark::State &state)
{
    for (const auto _ : state) {
        json->add_member("port", 8080);
        benchmark::DoNotOptimize(json);
    }
}

BENCHMARK_DEFINE_F(JsonBenchmark, JsonAddMemberUInt64)(benchmark::State &state)
{
    for (const auto _ : state) {
        json->add_member("large_number", 1234567890123456789ULL);
        benchmark::DoNotOptimize(json);
    }
}

BENCHMARK_REGISTER_F(JsonBenchmark, JsonAddMemberString);
BENCHMARK_REGISTER_F(JsonBenchmark, JsonAddMemberInt);
BENCHMARK_REGISTER_F(JsonBenchmark, JsonAddMemberDouble);
BENCHMARK_REGISTER_F(JsonBenchmark, JsonAddMemberBool);
BENCHMARK_REGISTER_F(JsonBenchmark, JsonAddMemberJson);
BENCHMARK_REGISTER_F(JsonBenchmark, JsonAddMemberUInt16);
BENCHMARK_REGISTER_F(JsonBenchmark, JsonAddMemberUInt64);