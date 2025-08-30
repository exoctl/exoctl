Web.new(_engine.server, "/version", function(req)
    local version_json = Json:new():add("version",
        string.format("%d.%d.%d", _engine.version.major, _engine.version.minor, _engine.version.patch)):add("major",
        _engine.version.major):add("minor", _engine.version.minor):add("patch", _engine.version.patch):add("code",
        _engine.version.code)
        
    return Response:new(200, "application/json", version_json:tostring())
end)
