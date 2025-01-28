#pragma once

#ifndef _PLUGINS_APPLICATION
#define _PLUGINS_APPLICATION

#include <functional>
#include <engine/version.hxx>

static bool _plugins_engine_class = false;
if (!_plugins_engine_class) {
    int version = ENGINE_VERSION_CODE;
    std::function<std::any()> stop = [&]() -> std::any {
        ENGINE_INSTANCE.get()->stop();
        return {};
    };
    
    engine::plugins::Plugins::register_class("engine", &ENGINE_INSTANCE);
    engine::plugins::Plugins::register_class_member("engine", "version_code", version);
    engine::plugins::Plugins::register_class_member(
        "engine", "is_running", ENGINE_INSTANCE.get()->is_running);
    engine::plugins::Plugins::register_class_method("engine", "stop", stop);

    _plugins_engine_class = true;
}

#endif // _PLUGINS_APPLICATION