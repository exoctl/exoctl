#include <data/metadata.hxx>


BENCHMARK_DEFINE_F(MetadataBenchmark, MetadataParse)(benchmark::State &state)
{
    std::string test_string = "the best engine";
    for (auto _ : state)
    {
        metadata->metadata_parse(test_string);
    }
}

BENCHMARK_REGISTER_F(MetadataBenchmark, MetadataParse);
