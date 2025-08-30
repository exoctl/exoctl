local get_compiled_rules = { Server = nil, yara_manager = nil }

function get_compiled_rules:new()
    local obj = { methods = {} }
    setmetatable(obj, self)
    self.__index = self
    return obj
end

function get_compiled_rules:setup(server, yara_manager)
    assert(type(server) == "table", "Invalid server instance")
    assert(type(yara_manager) == "table", "Invalid yara_manager instance")

    self.Server = server
    self.yara_manager = yara_manager
end

function get_compiled_rules:load()
    self.Server:create_route("/compiled/rules", function(req)
        local yr_stream = Stream:new()
        local compiled_rules = ""
        yr_stream:write(function(data)
            compiled_rules = compiled_rules .. data
        end)
        
        self.yara_manager.yara:save_rules_stream(yr_stream)

        return Response:new(200, compiled_rules)
    end)
end

function get_compiled_rules:create_error_response(status, message)
    local json = Json:new()
    json:add("message", message)
    return Response:new(status, "application/json", json:tostring())
end

return get_compiled_rules