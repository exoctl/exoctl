local engine_json = Json:new()

local engine_fields = Json:new()
engine_fields:add("is_running", _engine.is_running)

local engine_server = Json:new():add("port", _engine.server.port):add("bindaddr", _engine.server.bindaddr):add(
"concurrency", _engine.server.concurrency):add("ssl_enable", _engine.server.ssl_enable)

engine_fields:add("server", engine_server)

engine_json:add("engine", engine_fields)

Web.new(_engine.server, "/status", function(req)
    return Response.new(200, "application/json", engine_json:to_string())
end, HTTPMethod.Get)
