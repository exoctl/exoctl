#include <parser/toml.hxx>

BENCHMARK_DEFINE_F(TomlBenchmark, TomlParserFile)(benchmark::State &state)
{
    for(auto _ : state)        
        toml->toml_parser_file("./configuration.toml"); 
}

BENCHMARK_DEFINE_F(TomlBenchmark, TomlGetTblString)(benchmark::State &state)
{
    for(auto _ : state)
    {
        std::string tbl_string = toml->toml_get_tbl_string("project", "name");
        benchmark::DoNotOptimize(tbl_string);
    }
}

BENCHMARK_DEFINE_F(TomlBenchmark, TomlGetTblUint16T)(benchmark::State& state)
{
    for (auto _ : state) {
        std::uint16_t test_short = toml->toml_get_tbl_uint16_t("log", "level");
        benchmark::DoNotOptimize(test_short);
    }
}

BENCHMARK_DEFINE_F(TomlBenchmark, TomlGetTblArray)(benchmark::State& state)
{
    for (auto _ : state) {
        toml::array array_test = toml->toml_get_tbl_array("crow", "websocket_conn_whitelist");
        benchmark::DoNotOptimize(array_test);
    }
}

BENCHMARK_REGISTER_F(TomlBenchmark, TomlParserFile);
BENCHMARK_REGISTER_F(TomlBenchmark, TomlGetTblString);
BENCHMARK_REGISTER_F(TomlBenchmark, TomlGetTblUint16T);
BENCHMARK_REGISTER_F(TomlBenchmark, TomlGetTblArray);
