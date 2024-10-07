#include <benchmark/benchmark.h>
#include <parser/json.hxx>
#include <vector>

BENCHMARK_DEFINE_F(JsonBenchmark, JsonAddMemberString)(benchmark::State &state)
{
    for (const auto _ : state) {
        json->add_member_string("name", "maldec");
        benchmark::DoNotOptimize(json);
    }
}

BENCHMARK_DEFINE_F(JsonBenchmark, JsonAddMemberInt)(benchmark::State &state)
{
    for (const auto _ : state) {
        json->add_member_int("age", 21);
        benchmark::DoNotOptimize(json);
    }
}

BENCHMARK_DEFINE_F(JsonBenchmark, JsonAddMemberDouble)(benchmark::State &state)
{
    for (const auto _ : state) {
        json->add_member_double("score", 99.5);
        benchmark::DoNotOptimize(json);
    }
}

BENCHMARK_DEFINE_F(JsonBenchmark, JsonAddMemberBool)(benchmark::State &state)
{
    for (const auto _ : state) {
        json->add_member_bool("is_active", true);
        benchmark::DoNotOptimize(json);
    }
}

BENCHMARK_DEFINE_F(JsonBenchmark, JsonAddMemberJson)(benchmark::State &state)
{
    Parser::Json inner_json;
    inner_json.add_member_string("inner_name", "inner_value");

    for (const auto _ : state) {
        json->add_member_json("inner_object", inner_json);
        benchmark::DoNotOptimize(json);
    }
}

BENCHMARK_DEFINE_F(JsonBenchmark, JsonAddMemberVector)(benchmark::State &state)
{
    std::vector<Parser::Json> json_vector;
    for (int i = 0; i < 5; ++i) {
        Parser::Json item;
        item.add_member_string("item_name", "value_" + std::to_string(i));
        json_vector.push_back(item);
    }

    for (const auto _ : state) {
        json->add_member_vector("json_array", json_vector);
        benchmark::DoNotOptimize(json);
    }
}

BENCHMARK_DEFINE_F(JsonBenchmark, JsonAddMemberUInt16)(benchmark::State &state)
{
    for (const auto _ : state) {
        json->add_member_uint16("port", 8080);
        benchmark::DoNotOptimize(json);
    }
}

BENCHMARK_DEFINE_F(JsonBenchmark, JsonAddMemberUInt64)(benchmark::State &state)
{
    for (const auto _ : state) {
        json->add_member_uint64("large_number", 1234567890123456789ULL);
        benchmark::DoNotOptimize(json);
    }
}

BENCHMARK_REGISTER_F(JsonBenchmark, JsonAddMemberString);
BENCHMARK_REGISTER_F(JsonBenchmark, JsonAddMemberInt);
BENCHMARK_REGISTER_F(JsonBenchmark, JsonAddMemberDouble);
BENCHMARK_REGISTER_F(JsonBenchmark, JsonAddMemberBool);
BENCHMARK_REGISTER_F(JsonBenchmark, JsonAddMemberJson);
BENCHMARK_REGISTER_F(JsonBenchmark, JsonAddMemberVector);
BENCHMARK_REGISTER_F(JsonBenchmark, JsonAddMemberUInt16);
BENCHMARK_REGISTER_F(JsonBenchmark, JsonAddMemberUInt64);