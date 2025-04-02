local DisableRules = { Server = nil, MYara = nil }

function DisableRules:new()
    local obj = { methods = {} }
    setmetatable(obj, self)
    self.__index = self
    return obj
end

function DisableRules:setup(server, myara)
    self.Server = server
    self.MYara = myara
end

function DisableRules:load()
    self.Server:create_route("/api/disable/yara/rule", HTTPMethod.Post, function(req)
        local json = Json:new()
        
        json:from_string(req.body)
        local rule = json:get("rule")

        if not rule then
            local message = Json:new()
            message:add("message", "Missing required fields: 'rule' are required.")
            return Response.new(400, "application/json", message:to_string())
        end
        
        local disabled = false
        
        self.MYara.yara:rules_foreach(function(rules)
            if (rules.identifier == rule) then
                disabled = true
                self.MYara.yara:rule_disable(rules)
            end
        end)
        
        local message = Json:new()
        
        if disabled then
            message:add("message", "Rule was enabled")
            return Response.new(200, "application/json", message:to_string())
        end
        
        message:add("message", "The rule was not found")
        return Response.new(400, "application/json", message:to_string())
    end)
end

return DisableRules
