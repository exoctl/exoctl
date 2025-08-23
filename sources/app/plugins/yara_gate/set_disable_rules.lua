local set_disable_rules = { server = nil, yara_manager = nil }

function set_disable_rules:new()
    local obj = { methods = {} }
    setmetatable(obj, self)
    self.__index = self
    return obj
end

function set_disable_rules:setup(server, yara_manager)
    assert(type(server) == "table", "Invalid server instance")
    assert(type(yara_manager) == "table", "Invalid yara_manager instance")

    self.server = server
    self.yara_manager = yara_manager
end

function set_disable_rules:load()
    local json = Json:new()
    self.server:create_route("/disable/rules", function(req)
        if not req.body or req.body == "" then
            return self:create_error_response(400, "Invalid request body")
        end

        local parse_success = pcall(function() json:from_string(req.body) end)
        if not parse_success then
            return self:create_error_response(400, "Invalid JSON format")
        end

        local rule = json:get("rule")
        if not rule or type(rule) ~= "string" or rule == "" then
            return self:create_error_response(400, "Missing or invalid field: 'rule' is required")
        end

        if not self.yara_manager or not self.yara_manager.is_life then
            return self:create_error_response(500, "Yara engine is not initialized")
        end

        local rule_found = false

        self.yara_manager.yara:rules_foreach(function(rules)
            if rules and rules.identifier == rule then
                rule_found = true
                self.yara_manager.yara:rule_disable(rules)
            end
        end)

        local message = Json:new()

        if rule_found then
            message:add("message", "Rule was disabled successfully")
            return Response:new(200, "application/json", message:tostring())
        end

        return self:create_error_response(404, "Rule not found")
    end)
end

function set_disable_rules:create_error_response(status, message)
    local json = Json:new()
    json:add("message", message)
    return Response:new(status, "application/json", json:tostring())
end

return set_disable_rules