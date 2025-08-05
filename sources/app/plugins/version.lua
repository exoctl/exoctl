local version_json = Json:new()

version_json:add("version_str",
    string.format("%d.%d.%d", _engine.version.major, _engine.version.minor, _engine.version.patch))
version_json:add("major", _engine.version.major)
version_json:add("minor", _engine.version.minor)
version_json:add("patch", _engine.version.patch)
version_json:add("code", _engine.version.code)

Web.new(_engine.server, "/version", function(req)
    return Response:new(200, "application/json", version_json:tostring())
end)
