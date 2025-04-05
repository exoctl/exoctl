local EnableRules = { Server = nil, MYara = nil }

function EnableRules:new()
    local obj = { methods = {} }
    setmetatable(obj, self)
    self.__index = self
    return obj
end

function EnableRules:setup(server, myara)
    assert(type(server) == "table", "Invalid server instance")
    assert(type(myara) == "table", "Invalid MYara instance")

    self.Server = server
    self.MYara = myara
end

function EnableRules:load()
    local json = Json:new()
    self.Server:create_route("/api/enable/yara/rule", HTTPMethod.Post, function(req)
        if not req.body or req.body == "" then
            return self:create_error_response(400, "Invalid request body")
        end

        local parse_success, err = pcall(function() json:from_string(req.body) end)
        if not parse_success then
            return self:create_error_response(400, "Invalid JSON format")
        end

        local rule = json:get("rule")
        if not rule or type(rule) ~= "string" or rule == "" then
            return self:create_error_response(400, "Missing or invalid field: 'rule' is required")
        end

        if not self.MYara or not self.MYara.is_life then
            return self:create_error_response(500, "Yara engine is not initialized")
        end

        local rule_found = false

        self.MYara.yara:rules_foreach(function(rules)
            if rules and rules.identifier == rule then
                rule_found = true
                self.MYara.yara:rule_enable(rules)
            end
        end)

        local message = Json:new()

        if rule_found then
            message:add("message", "Rule was enabled successfully")
            return Response:new(200, "application/json", message:to_string())
        end

        return self:create_error_response(404, "Rule not found")
    end)
end

function EnableRules:create_error_response(status, message)
    local json = Json:new()
    json:add("message", message)
    return Response:new(status, "application/json", json:to_string())
end

return EnableRules
