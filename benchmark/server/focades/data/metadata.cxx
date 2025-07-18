#include <fmt/core.h>
#include <server/focades/data/metadata.hxx>

BENCHMARK_DEFINE_F(MetadataBenchmark, MetadataParse)(benchmark::State &state)
{
    std::string test_string = fmt::format("{}", state.range(0));

    for (auto _ : state) {
        benchmark::DoNotOptimize(test_string);

        metadata->parse(
            test_string,
            [&](engine::bridge::focades::data::metadata::record::DTO *p_dto) {
                benchmark::DoNotOptimize(p_dto);
            });
    }

    state.SetBytesProcessed(static_cast<int64_t>(state.iterations()) *
                            static_cast<int64_t>(test_string.size()));
}

BENCHMARK_REGISTER_F(MetadataBenchmark, MetadataParse)
    ->Arg(16)
    ->Arg(64)
    ->Arg(256)
    ->Arg(1024)
    ->Arg(4096);
