local engine_fields = Json:new()
engine_fields:add("is_running", _engine.is_running)

local engine_database = Json:new():add("is_running", _engine.database.is_running):add("sql_queue_size",
    _engine.database.sql_queue_size)
local engine_server = Json:new():add("port", _engine.server.port):add("bindaddr", _engine.server.baddr):add(
    "concurrency", _engine.server.concurrency):add("ssl_enable", _engine.server.ssl_enable)

engine_fields:add("database", engine_database)
engine_fields:add("server", engine_server)

engine_fields:add("configuration", _engine.configuration:tojson())

local engine_json = Json:new()
engine_json:add("engine", engine_fields)

Web.new(_engine.server, "/status", function(req)
    if (req.method ~= HTTPMethod.GET) then
        return Response:new(401)
    end
    return Response:new(200, "application/json", engine_json:tostring())
end)
