local yara <const> = Yara:new()

yara:load_rules(function()
    local rule = [[
        rule Malware { condition: true }
    ]]
    if (yara:set_rule_buff(rule, "teste") ~= 0) then
        _engine.logging:error("There is a problem loading the rule, check for possible syntax errors")
    end
end)

-- local yr = Stream:new()
-- yr:write(function(data, size, count)
--     local arquivo = "dados.yarc"
--     local f = io.open(arquivo, "a")
--     if not f then
--         error(" " .. arquivo)
--     end

--     --f:write(data)
--     f:close()

--     return 1
-- end)

yara:scan_bytes("buffer", function(message, data)
    if (message == 1) then
        local rule = data
        print(rule.identifier)
        print(rule.ns.name)
    elseif (message == 3) then
        print("AAAAAAAAAAA")
    end
    return 0
end, 2)

yara:scan_bytes("buffer", function(message, data)
    if (message == 1) then
        local rule = data
        print(rule.identifier)
        print(rule.ns.name)
    elseif (message == 3) then
        print("FUNCIONAA")
    end
    return 0
end, 2)


-- print("save = ", yara:save_rules_stream(yr))

local engine_json = Json:new()

local engine_fields = Json:new()
engine_fields:add("is_running", _engine.is_running)

local engine_server = Json:new()
engine_server:add("port", _engine.server.port)
engine_server:add("bindaddr", _engine.server.bindaddr)
engine_server:add("concurrency", _engine.server.concurrency)
engine_server:add("ssl_enable", _engine.server.ssl_enable)

engine_fields:add("server", engine_server)

engine_json:add("engine", engine_fields)

Web.new(_engine.server, "/engine/status", function (req)
    return Response.new(200, "application/json", engine_json:to_string())
end, HTTPMethod.Get)

Web.new(_engine.server, "/engine/test", function (req)
    print(req.body)
    local json = Json:new()
    json:add("message", "data received successfully")
    return Response.new(200, "application/json", json:to_string())
end, HTTPMethod.Post)

-- yara:unload_compiler()
-- yara:unload_stream_rules()
