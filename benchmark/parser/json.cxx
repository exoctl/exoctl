#include <parser/json.hxx>

BENCHMARK_DEFINE_F(JsonBenchmark, JsonCraft)(benchmark::State &state)
{
    nlohmann::json test_json = {"name", "maldec"};
    for(auto _ : state)
        json->json_craft(test_json);
}

BENCHMARK_DEFINE_F(JsonBenchmark, JsonToString)(benchmark::State &state)
{
    for(auto _ : state)
    {
        std::string string_json = json->json_to_string();
        benchmark::DoNotOptimize(string_json);
    }
}

BENCHMARK_REGISTER_F(JsonBenchmark, JsonCraft);
BENCHMARK_REGISTER_F(JsonBenchmark, JsonToString);
