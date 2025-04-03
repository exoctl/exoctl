local LoadRules = { Server = nil, MYara = nil }

function LoadRules:new()
    local obj = { methods = {} }
    setmetatable(obj, self)
    self.__index = self
    return obj
end

function LoadRules:setup(server, myara)
    assert(type(server) == "table", "Invalid server instance")
    assert(type(myara) == "table", "Invalid MYara instance")
    
    self.Server = server
    self.MYara = myara
end

function LoadRules:load()
    self.Server:create_route("/api/load/yara/rule", HTTPMethod.Post, function(req)
        local success, response = pcall(function()
            local json = Json:new()
            
            if not req.body or #req.body == 0 then
                return self:create_error_response(400, "Empty request body")
            end
            
            local parse_success = pcall(function() json:from_string(req.body) end)
            if not parse_success then
                return self:create_error_response(400, "Invalid JSON format")
            end

            local rule = json:get("rule")
            local namespace = json:get("namespace")

            if type(rule) ~= "string" or type(namespace) ~= "string" or #rule == 0 or #namespace == 0 then
                return self:create_error_response(400, "Invalid or missing 'rule' and 'namespace'")
            end

            self.MYara:backup_save_rules()
            self.MYara:reload()

            local compiled_rule = true
            
            self.MYara:load_rules_saved()
            if self.MYara.yara:set_rule_buff(rule, namespace) ~= 0 then
                self.MYara:reload()
                compiled_rule = false
            end
            
            self.MYara:load()

            local message = Json:new()

            if compiled_rule then
                
                self.MYara:save_rule(rule, namespace)
                self.MYara:backup_save_rules()
                
                message:add("message", "Rule compiled successfully")
                return Response.new(200, "application/json", message:to_string())
            end

            self.MYara:backup_recover_rules()
            return self:create_error_response(400, "Rule compilation failed. Check syntax.")
        end)

        if not success then
            return self:create_error_response(500, "Internal Server Error")
        end

        return response
    end)
end

function LoadRules:create_error_response(status, message)
    local json = Json:new()
    json:add("message", message)
    return Response.new(status, "application/json", json:to_string())
end

return LoadRules
