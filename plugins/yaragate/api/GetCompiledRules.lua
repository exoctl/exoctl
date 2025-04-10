local GetCompiledRules = { Server = nil, MYara = nil }

function GetCompiledRules:new()
    local obj = { methods = {} }
    setmetatable(obj, self)
    self.__index = self
    return obj
end

function GetCompiledRules:setup(server, myara)
    assert(type(server) == "table", "Invalid server instance")
    assert(type(myara) == "table", "Invalid MYara instance")

    self.Server = server
    self.MYara = myara
end

function GetCompiledRules:load()
    self.Server:create_route("/api/get/compiled/rules", HTTPMethod.Get, function(req)
        local yr_stream = Stream:new()
        local compiled_rules = ""
        yr_stream:write(function(data)
            compiled_rules = compiled_rules .. data
        end)
        
        self.MYara.yara:save_rules_stream(yr_stream)

        return Response:new(200, compiled_rules)
    end)
end

function GetCompiledRules:create_error_response(status, message)
    local json = Json:new()
    json:add("message", message)
    return Response:new(status, "application/json", json:to_string())
end

return GetCompiledRules
