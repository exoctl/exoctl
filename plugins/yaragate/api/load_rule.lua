local LoadRule = { Server = nil, MYara = nil }

function LoadRule:new()
    local obj = { methods = {} }
    setmetatable(obj, self)
    self.__index = self
    return obj
end

function LoadRule:setup(server, myara)
    self.Server = server
    self.MYara = myara
end

function LoadRule:load()
    self.Server:create_route("/api/load/yara/rule", HTTPMethod.Post, function(req)
        local json = Json:new()

        json:from_string(req.body)

        local rule = json:get("rule")
        local namespace = json:get("namespace")

        if not rule or not namespace then
            local message = Json:new()

            message:add("message", "Missing required fields: 'rule' and 'namespace' are required.")

            return Response.new(400, "application/json", message:to_string())
        end

        -- Reload Yara with new rule
        self.MYara:backup_save_rules()
        self.MYara:reload()
        local compiled_rule = true

        self.MYara.yara:load_rules(function()
            if (self.MYara.yara:set_rule_buff(rule, namespace) ~= 0) then
                self.MYara:reload()
                compiled_rule = false
            end
            self.MYara:load_rules_saved()
        end)
        
        local message = Json:new()
        
        if compiled_rule then
            self.MYara:backup_save_rules() -- Backup rules
            self.MYara:save_rule(rule, namespace)
            
            message:add("message", "Rule compiled successfully")
            return Response.new(200, "application/json", message:to_string())
        end

        self.MYara:backup_recover_rules()

        message:add("message", "The rule was not compiled successfully, check for possible syntax errors")
        return Response.new(400, "application/json", message:to_string())
    end)
end

return LoadRule
