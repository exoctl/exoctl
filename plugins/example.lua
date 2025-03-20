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

print(_analysis.scan.yara.rules_loaded_count)

_analysis.scan.yara:scan_bytes("buffer", function(message, data)
    if (message == 1) then
        local rule = data
        print(rule.identifier)
        print(rule.ns.name)
    elseif (message == 3) then
        print("Scan acabou !!")
    end
    return 0
end, 1)


-- print("save = ", yara:save_rules_stream(yr))

Web.new(_engine.server, "/engine", function(req)
    if (req.keep_alive) then
        local json = Json:new()
        _analysis.scan.yara:rules_foreach(function(rule)
            _analysis.scan.yara:metas_foreach(rule, function(meta)
                local value = function()
                    if (meta.type ~= 2) then
                        return meta.integer
                    else
                        return meta.string
                    end
                end

                _engine.logging:info(meta.identifier .. " = " .. value())
            end)

            local rules = Json:new()
            rules:add("name", rule.identifier)
            rules:add("ns.name", rule.ns.name)

            json:add(rule.identifier, rules)
        end)

        local res = Response.new(200, "application/json", json:to_string())

        res:add_header("Jwt", "Token")

        return res
    end
end, HTTPMethod.Get)

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
