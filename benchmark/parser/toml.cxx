#include <parser/toml.hxx>

BENCHMARK_DEFINE_F(TomlBenchmark, TomlParse)(benchmark::State &state)
{
    static constexpr std::string_view some_toml = R"(
        [project]
        name = "Engine"
        version = 1
       )"sv;

    for (const auto _ : state)
        toml->parse_buffer(some_toml);
}

BENCHMARK_DEFINE_F(TomlBenchmark, TomlGetTblString)(benchmark::State &state)
{
    for (const auto _ : state) {
        std::string tbl_string =
            toml->get_tbl()["project"]["name"].value<std::string>().value();
        benchmark::DoNotOptimize(tbl_string);
    }
}

BENCHMARK_DEFINE_F(TomlBenchmark, TomlGetTblUint16)(benchmark::State &state)
{
    for (const auto _ : state) {
        std::uint16_t test_short = toml->get_tbl()["project"]["version"]
                                       .value<std::uint16_t>()
                                       .value();
        benchmark::DoNotOptimize(test_short);
    }
}

BENCHMARK_REGISTER_F(TomlBenchmark, TomlParse);
BENCHMARK_REGISTER_F(TomlBenchmark, TomlGetTblString);
BENCHMARK_REGISTER_F(TomlBenchmark, TomlGetTblUint16);
