#pragma once

#ifndef _PLUGINS_ENGINE
#define _PLUGINS_ENGINE

static bool _plugins_server_class = false;
if (!_plugins_server_class) {
    // register class server
    plugins::Plugins::register_class("server", &SERVER_INSTANCE);
    plugins::Plugins::register_class_member(
        "server", "port", SERVER_INSTANCE.port);
    plugins::Plugins::register_class_member(
        "server", "bindaddr", SERVER_INSTANCE.bindaddr);
    plugins::Plugins::register_class_member(
        "server", "concurrency", SERVER_INSTANCE.concurrency);
    _plugins_server_class = true;
}

#endif // _PLUGINS_ENGINE