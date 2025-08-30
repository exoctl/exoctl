#pragma once

#include <engine/bridge/endpoints/analysis/analysis.hxx>

namespace engine::bridge::endpoints::analysis
{
    class Families
    {
    public:
        static void setup(Analysis &analysis);
    };
} // namespace engine::bridge::endpoints::analysis