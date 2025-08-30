local set_load_rules = { server = nil, yara_manager = nil }

function set_load_rules:new()
    local obj = { methods = {} }
    setmetatable(obj, self)
    self.__index = self
    return obj
end

function set_load_rules:setup(server, yara_manager)
    assert(type(server) == "table", "Invalid server instance")
    assert(type(yara_manager) == "table", "Invalid yara_manager instance")

    self.server = server
    self.yara_manager = yara_manager
end

function set_load_rules:load()
    local json = Json:new()
    self.server:create_route("/load/rules", function(req)
        if not req.body or #req.body == 0 then
            return self:create_error_response(400, "Empty request body")
        end

        json:from_string(req.body)
        local rule = json:get("rule")
        local namespace = json:get("namespace")

        if type(rule) ~= "string" or type(namespace) ~= "string" or #rule == 0 or #namespace == 0 then
            return self:create_error_response(400, "Invalid or missing 'rule' and 'namespace'")
        end

        self.server.logging:info("Is Yara rules alive? " .. tostring(self.yara_manager.is_life))
        if self.yara_manager.is_life then
            self.yara_manager:backup_save_rules()
            self.yara_manager:reload()

            local message = Json:new()

            if self.yara_manager.yara:set_rule_buff(rule, namespace) == 0 then
                self.yara_manager:save_rule(rule, namespace)
                self.yara_manager.yara:set_rules_folder(self.yara_manager.rules_path)
                self.yara_manager:load()
                self.yara_manager:backup_save_rules()

                message:add("message", "Rule compiled successfully")
                return Response:new(200, "application/json", message:tostring())
            else
                self.yara_manager:reload()
                self.yara_manager:backup_recover_rules()
                return self:create_error_response(400,
                    "Rule compilation failed. Check syntax or rule no longer exists namespace")
            end
        end

        return self:create_error_response(400, "Please wait, we are compiling other rules ...")
    end)
end

function set_load_rules:create_error_response(status, message)
    local json = Json:new()
    json:add("message", message)
    return Response:new(status, "application/json", json:tostring())
end

return set_load_rules
