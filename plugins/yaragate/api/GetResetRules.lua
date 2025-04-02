local GetResetRules = { Server = nil, MYara = nil }

function GetResetRules:new()
    local obj = { methods = {} }
    setmetatable(obj, self)
    self.__index = self
    return obj
end

function GetResetRules:setup(server, myara)
    self.Server = server
    self.MYara = myara
end

function GetResetRules:load()
    self.Server:create_route("/api/get/reset/rules", HTTPMethod.Get, function(req)
        local response = Json:new()
        response:add("reset_time", self.MYara.reset_time)
        return Response.new(200, "application/json", response:to_string())
    end)
end

return GetResetRules
